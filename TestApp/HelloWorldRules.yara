rule HelloWorld
{
    strings:
        $hw = "Hello World!"

    condition:
        $hw
}
