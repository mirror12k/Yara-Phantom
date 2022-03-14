
rule what_kind_of_a_rule
{
    meta:
        author = "nothing to see here"
    strings:
        $a = {D0 CF 11 E0}
    condition:
        $a
}