rule BasicRule
{
    strings:
        $test: "hello world"

    condition:
        $test
}
