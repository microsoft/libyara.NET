rule HelloWorld : HelloTag
{
    strings:
        $hw = "Hello World"

    condition:
        $hw
}
