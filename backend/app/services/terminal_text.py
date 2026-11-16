"""ターミナルの画面出力を、読めるテキストに直す

再生用の記録（asciicast）には、色の指定・カーソル移動・Backspace での打ち直し・--More-- の消去などの
制御文字がそのまま入っている。ここでは端末の動きを行単位で再現し、最終的に画面に残った文字だけを取り出す。

- 1 行の中の編集（行頭へ戻る、Backspace、行の消去、カーソルの左右移動、文字の挿入・削除）を反映する
- 色などの装飾、ウィンドウタイトルの設定は捨てる
- 行は折り返さない（長い設定行を途中で切らないため。端末の幅には合わせない）
- vi や top のように画面全体を書き換える操作は再現しない（カーソルの上下移動・位置指定は改行として扱う）
"""
import json
import re
from collections.abc import Iterable

# ESC で始まる制御シーケンス: CSI（ESC [ ... 終端文字）、OSC（ESC ] ... BEL か ESC \\）、その他 2〜3 文字のもの
_ESC = re.compile(
    r"\x1b(?:"
    r"\[(?P<params>[0-9;?<=>!]*)(?P<inter>[ -/]*)(?P<final>[@-~])"
    r"|\](?:[^\x07\x1b]*)(?:\x07|\x1b\\)"
    r"|[()*+][0-9A-Za-z]"
    r"|[=>78cDEHMNOZ]"
    r")"
)
# シーケンスが出力の区切りで途中までしか届いていないとき、次の出力とつなげるために取っておく部分
_PARTIAL = re.compile(r"\x1b(?:\[[0-9;?<=>!]*[ -/]*|\][^\x07\x1b]*\x1b?|[()*+])?$")
MAX_LINE = 20000  # 1 行の上限（壊れた出力で際限なく伸びないように）


class Renderer:
    def __init__(self) -> None:
        self.lines: list[str] = []
        self.line: list[str] = []  # いまの行
        self.col = 0  # カーソルの位置（文字数）
        self._pending = ""  # 途中までしか届いていない制御シーケンス

    def _newline(self) -> None:
        self.lines.append("".join(self.line).rstrip())
        self.line, self.col = [], 0

    def _put(self, ch: str) -> None:
        if self.col >= MAX_LINE:
            return
        if self.col < len(self.line):
            self.line[self.col] = ch
        else:
            self.line.extend(" " * (self.col - len(self.line)))
            self.line.append(ch)
        self.col += 1

    def _csi(self, params: str, final: str) -> None:
        nums = [int(x) if x.isdigit() else 0 for x in params.split(";")] if params and params[0] not in "?<=>!" else [0]
        n = nums[0]
        if final == "K":  # 行の消去: 0=カーソルから行末、1=行頭からカーソル、2=行全体
            if n == 0:
                del self.line[self.col:]
            elif n == 1:
                end = min(self.col + 1, len(self.line))
                self.line[:end] = [" "] * end
            else:
                self.line = []
        elif final == "D":  # 左へ
            self.col = max(0, self.col - (n or 1))
        elif final == "C":  # 右へ
            self.col = min(MAX_LINE, self.col + (n or 1))
        elif final == "G":  # 桁の指定（1 始まり）
            self.col = min(MAX_LINE, max(0, (n or 1) - 1))
        elif final == "P":  # 文字の削除
            del self.line[self.col:self.col + (n or 1)]
        elif final == "@" and self.col < len(self.line):  # 空白の挿入（行末より先なら何もしない）
            self.line[self.col:self.col] = [" "] * (n or 1)
        elif final == "X":  # 文字を空白にする
            for i in range(self.col, min(self.col + (n or 1), len(self.line))):
                self.line[i] = " "
        elif final == "@":
            pass
        elif final in "ABEFHfdJ" and self.line:
            # 上下の移動・位置指定・画面の消去 → 画面全体の書き換えは再現しない。行を改める
            self._newline()
        # m（色）、h / l（モード）などは何もしない

    def feed(self, data: str) -> None:
        data = self._pending + data
        self._pending = ""
        m = _PARTIAL.search(data)
        if m and m.group(0):
            self._pending, data = m.group(0), data[:m.start()]
        pos = 0
        while pos < len(data):
            ch = data[pos]
            if ch == "\x1b":
                m = _ESC.match(data, pos)
                if m:
                    if m.group("final"):
                        self._csi(m.group("params") or "", m.group("final"))
                    pos = m.end()
                    continue
                pos += 1  # 解釈できない ESC は捨てる
                continue
            pos += 1
            if ch == "\n":
                self._newline()
            elif ch == "\r":
                self.col = 0
            elif ch in "\b\x7f":
                self.col = max(0, self.col - 1)
            elif ch == "\t":
                for _ in range(8 - self.col % 8):
                    self._put(" ")
            elif ch >= " ":
                self._put(ch)
            # それ以外の制御文字（BEL など）は捨てる

    def text(self) -> str:
        lines = [*self.lines, "".join(self.line).rstrip()]
        while lines and not lines[-1]:
            lines.pop()
        return "\n".join(lines) + ("\n" if lines else "")


def render(chunks: Iterable[str]) -> str:
    r = Renderer()
    for c in chunks:
        r.feed(c)
    return r.text()


def cast_to_text(cast: str) -> str:
    """asciicast v2 の記録から、画面出力（"o" のイベント）だけをつないでテキストにする"""
    def outputs():
        for i, line in enumerate(cast.splitlines()):
            if i == 0 or not line.strip():  # 1 行目はヘッダー
                continue
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            if isinstance(ev, list) and len(ev) >= 3 and ev[1] == "o" and isinstance(ev[2], str):
                yield ev[2]
    return render(outputs())
