rule ExampleRule1
{
    strings:
        $ex = "example 1"

    condition:
        $ex
}

rule ExampleRule2
{
    strings:
        $ex = "example 2"

    condition:
        $ex
}
