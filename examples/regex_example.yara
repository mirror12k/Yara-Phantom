/* my comment */

rule IP {
    meta:
        author = "not anything at all"
    strings:
        $ipv4 = /(\d{1,3}\.){3}\d{1,3}/ wide ascii
    condition:
        any of them
}
