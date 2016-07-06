rule BasicRule
{
    strings:
        $hw = "hello world"

    condition:
        $hw
}
