from typing import NewType, cast

ColoredString = NewType("ColoredString", str)


class Color:
    """Used to colorify terminal output.
    Taken nearly verbatim from gef, https://github.com/hugsy/gef/blob/ecd6f8ff638d34043045df169ca6062b2fb28819/gef.py#L366-L421

gef is distributed under the MIT License (MIT)
Copyright (c) 2013-2019 crazy rabbidz

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
    """

    colors = {
        "normal": "\033[0m",
        "gray": "\033[1;38;5;240m",
        "red": "\033[31m",
        "green": "\033[32m",
        "yellow": "\033[33m",
        "blue": "\033[34m",
        "pink": "\033[35m",
        "cyan": "\033[36m",
        "bold": "\033[1m",
        "underline": "\033[4m",
        "underline_off": "\033[24m",
        "highlight": "\033[3m",
        "highlight_off": "\033[23m",
        "blink": "\033[5m",
        "blink_off": "\033[25m",
    }

    disable_colors = False

    @staticmethod
    def redify(msg: str) -> ColoredString:
        return Color.colorify(msg, "red")

    @staticmethod
    def greenify(msg: str) -> ColoredString:
        return Color.colorify(msg, "green")

    @staticmethod
    def blueify(msg: str) -> ColoredString:
        return Color.colorify(msg, "blue")

    @staticmethod
    def yellowify(msg: str) -> ColoredString:
        return Color.colorify(msg, "yellow")

    @staticmethod
    def grayify(msg: str) -> ColoredString:
        return Color.colorify(msg, "gray")

    @staticmethod
    def pinkify(msg: str) -> ColoredString:
        return Color.colorify(msg, "pink")

    @staticmethod
    def cyanify(msg: str) -> ColoredString:
        return Color.colorify(msg, "cyan")

    @staticmethod
    def boldify(msg: str) -> ColoredString:
        return Color.colorify(msg, "bold")

    @staticmethod
    def underlinify(msg: str) -> ColoredString:
        return Color.colorify(msg, "underline")

    @staticmethod
    def highlightify(msg: str) -> ColoredString:
        return Color.colorify(msg, "highlight")

    @staticmethod
    def blinkify(msg: str) -> ColoredString:
        return Color.colorify(msg, "blink")

    @staticmethod
    def colorify(text: str, attrs: str) -> ColoredString:
        """Color text according to the given attributes.
        :param str text:
        :param
        :return str:
        """
        if Color.disable_colors is True:
            return cast(ColoredString, text)

        colors = Color.colors
        msg = [colors[attr] for attr in attrs.split() if attr in colors]
        msg.append(text)
        if colors["highlight"] in msg:
            msg.append(colors["highlight_off"])
        if colors["underline"] in msg:
            msg.append(colors["underline_off"])
        if colors["blink"] in msg:
            msg.append(colors["blink_off"])
        msg.append(colors["normal"])
        return cast(ColoredString, "".join(msg))
