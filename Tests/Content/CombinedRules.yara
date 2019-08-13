rule ExampleRule1 : HelloTag
{
    strings:
        $ex = "example 1"

    condition:
        $ex
}

rule ExampleRule2 : HelloTag HelloTag2
{
    strings:
        $ex = "example 2"

    condition:
        $ex
}
