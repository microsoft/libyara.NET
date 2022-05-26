rule BasicRule
{
    meta:
        description = "This is a meta field"

    strings:
        $hw = "hello world"

    condition:
        $hw
}
