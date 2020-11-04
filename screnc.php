<?php

/**
 * Inspired by CyberChef
 * https://github.com/gchq/CyberChef/blob/master/src/core/operations/MicrosoftScriptDecoder.mjs
 */
class WindowsScriptEncoder
{
    private static $D_TABLE = [
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "\x57\x6E\x7B",
        "\x4A\x4C\x41",
        "\x0B\x0B\x0B",
        "\x0C\x0C\x0C",
        "\x4A\x4C\x41",
        "\x0E\x0E\x0E",
        "\x0F\x0F\x0F",
        "\x10\x10\x10",
        "\x11\x11\x11",
        "\x12\x12\x12",
        "\x13\x13\x13",
        "\x14\x14\x14",
        "\x15\x15\x15",
        "\x16\x16\x16",
        "\x17\x17\x17",
        "\x18\x18\x18",
        "\x19\x19\x19",
        "\x1A\x1A\x1A",
        "\x1B\x1B\x1B",
        "\x1C\x1C\x1C",
        "\x1D\x1D\x1D",
        "\x1E\x1E\x1E",
        "\x1F\x1F\x1F",
        "\x2E\x2D\x32",
        "\x47\x75\x30",
        "\x7A\x52\x21",
        "\x56\x60\x29",
        "\x42\x71\x5B",
        "\x6A\x5E\x38",
        "\x2F\x49\x33",
        "\x26\x5C\x3D",
        "\x49\x62\x58",
        "\x41\x7D\x3A",
        "\x34\x29\x35",
        "\x32\x36\x65",
        "\x5B\x20\x39",
        "\x76\x7C\x5C",
        "\x72\x7A\x56",
        "\x43\x7F\x73",
        "\x38\x6B\x66",
        "\x39\x63\x4E",
        "\x70\x33\x45",
        "\x45\x2B\x6B",
        "\x68\x68\x62",
        "\x71\x51\x59",
        "\x4F\x66\x78",
        "\x09\x76\x5E",
        "\x62\x31\x7D",
        "\x44\x64\x4A",
        "\x23\x54\x6D",
        "\x75\x43\x71",
        "\x4A\x4C\x41",
        "\x7E\x3A\x60",
        "\x4A\x4C\x41",
        "\x5E\x7E\x53",
        "\x40\x4C\x40",
        "\x77\x45\x42",
        "\x4A\x2C\x27",
        "\x61\x2A\x48",
        "\x5D\x74\x72",
        "\x22\x27\x75",
        "\x4B\x37\x31",
        "\x6F\x44\x37",
        "\x4E\x79\x4D",
        "\x3B\x59\x52",
        "\x4C\x2F\x22",
        "\x50\x6F\x54",
        "\x67\x26\x6A",
        "\x2A\x72\x47",
        "\x7D\x6A\x64",
        "\x74\x39\x2D",
        "\x54\x7B\x20",
        "\x2B\x3F\x7F",
        "\x2D\x38\x2E",
        "\x2C\x77\x4C",
        "\x30\x67\x5D",
        "\x6E\x53\x7E",
        "\x6B\x47\x6C",
        "\x66\x34\x6F",
        "\x35\x78\x79",
        "\x25\x5D\x74",
        "\x21\x30\x43",
        "\x64\x23\x26",
        "\x4D\x5A\x76",
        "\x52\x5B\x25",
        "\x63\x6C\x24",
        "\x3F\x48\x2B",
        "\x7B\x55\x28",
        "\x78\x70\x23",
        "\x29\x69\x41",
        "\x28\x2E\x34",
        "\x73\x4C\x09",
        "\x59\x21\x2A",
        "\x33\x24\x44",
        "\x7F\x4E\x3F",
        "\x6D\x50\x77",
        "\x55\x09\x3B",
        "\x53\x56\x55",
        "\x7C\x73\x69",
        "\x3A\x35\x61",
        "\x5F\x61\x63",
        "\x65\x4B\x50",
        "\x46\x58\x67",
        "\x58\x3B\x51",
        "\x31\x57\x49",
        "\x69\x22\x4F",
        "\x6C\x6D\x46",
        "\x5A\x4D\x68",
        "\x48\x25\x7C",
        "\x27\x28\x36",
        "\x5C\x46\x70",
        "\x3D\x4A\x6E",
        "\x24\x32\x7A",
        "\x79\x41\x2F",
        "\x37\x3D\x5F",
        "\x60\x5F\x4B",
        "\x51\x4F\x5A",
        "\x20\x42\x2C",
        "\x36\x65\x57"
    ];

    private static $D_COMBINATION = [
        0, 1, 2, 0, 1, 2, 1, 2, 2, 1, 2, 1, 0, 2, 1, 2, 0, 2, 1, 2, 0, 0, 1, 2, 2, 1, 0, 2, 1, 2, 2, 1,
        0, 0, 2, 1, 2, 1, 2, 0, 2, 0, 0, 1, 2, 0, 2, 1, 0, 2, 1, 2, 0, 0, 1, 2, 2, 0, 0, 1, 2, 0, 2, 1
    ];
    
    /**
     * decode
     *
     * @param  string $encoded_code
     * @return string $decoded_code
     */
    public static function decode(string $data): string
    {
        if (strlen($data) < 24) {
            echo '[-] Invalid data' . PHP_EOL;
            return "";
        }

        $matcher = "/#@~\^.{6}==(.+).{6}==\^#~@/";
        $_data_size = 0;
        $_check_sum = 0;
        if (preg_match_all($matcher, $data, $match)) {
            $_data_size = unpack('I', base64_decode(substr($data, 4, 12)))[1];
            $_check_sum = unpack('I', base64_decode(substr($data, strlen($data) - 12, 8)))[1];
            $data = substr($data, 12, strlen($data) - 24);
        } else {
            echo '[-] Invalid format' . PHP_EOL;
            return "";
        }

        if (strlen($data) !== $_data_size) {
            echo '[-] Invalid data size' . PHP_EOL;
            return "";
        }

        $result = "";
        $index = -1;
        $check_sum = 0;

        $data = str_replace("@&", "\n", $data);
        $data = str_replace("@#", "\r", $data);
        $data = str_replace("@*", ">", $data);
        $data = str_replace("@!", "<", $data);
        $data = str_replace("@$", "@", $data);

        for ($i = 0; $i < strlen($data); $i++) {
            $char = $data[$i];
            $byte = ord($char);

            if ($byte < 128) {
                $index++;
            }

            if (($byte === 9 || $byte > 31 && $byte < 128) &&
                $byte !== 60 &&
                $byte !== 62 &&
                $byte !== 64
            ) {
                $char = self::$D_TABLE[$byte][self::$D_COMBINATION[$index % 64]];
            }

            $check_sum += ord($char);
            $check_sum %= 0x100000000;

            $result .= $char;
        }

        if ($check_sum !== $_check_sum) {
            echo '[-] Invalid checksum' . PHP_EOL;
            return "";
        }

        return $result;
    }
    
    /**
     * encode
     *
     * @param  string $plane_code
     * @return string $encoded_code
     */
    public static function encode(string $code): string
    {
        $check_sum = 0;
        for ($i = 0; $i < strlen($code); $i++) {
            $check_sum += ord($code[$i]);
            $check_sum %= 0x100000000;
        }
        $check_sum = base64_encode(pack("I", $check_sum));

        $result = "";
        $index = 0;
        for ($i = 0; $i < strlen($code); $i++) {
            $char = $code[$i];
            $p = self::$D_COMBINATION[$index % 64];

            for ($j = 9; $j < count(self::$D_TABLE); $j++) {
                if (self::$D_TABLE[$j][$p] === $char) {
                    if (($j === 9 || $j > 31 && $j < 128) &&
                        $j !== 60 &&
                        $j !== 62 &&
                        $j !== 64
                    ) {
                        $char = chr($j);
                        break;
                    }
                }
            }

            if (ord($char) < 128) {
                $index++;
            }

            $result .= $char;
        }

        $result = str_replace("@", "@$", $result);
        $result = str_replace("<", "@!", $result);
        $result = str_replace(">", "@*", $result);
        $result = str_replace("\r", "@#", $result);
        $result = str_replace("\n", "@&", $result);

        $data_size = strlen($result);
        $data_size = base64_encode(pack("I", $data_size));

        $result = "#@~^" . $data_size . $result . $check_sum . "^#~@";

        return $result;
    }
}
