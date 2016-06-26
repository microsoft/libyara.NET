#pragma once

#include <yara.h>

namespace libyaraNET {

    public ref class Match
    {
    public:
        property uint64_t Base;
        property uint64_t Offset;
        property array<uint8_t>^ Data;

        Match(YR_MATCH* match)
        {
            Base = match->base;
            Offset = match->offset;
            Data = gcnew array<uint8_t>(match->data_length);
        }

        System::String^ AsString()
        {
            return System::BitConverter::ToString(Data);
        }
    };
}
