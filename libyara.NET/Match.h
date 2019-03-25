#pragma once

#include <yara.h>

using namespace System::Text;

namespace libyaraNET {

    public ref class Match sealed
    {
    public:
        property uint64_t Base;
        property uint64_t Offset;
        property array<uint8_t>^ Data;

        /// <summary>
        /// Create an empty match. Useful for testing.
        /// </summary>
        Match()
        {
            Base = 0;
            Offset = 0;
            Data = gcnew array<uint8_t>(0);
        }

        Match(YR_MATCH* match)
        {
            Base = match->base;
            Offset = match->offset;

            Data = gcnew array<uint8_t>(match->match_length);
            Marshal::Copy(
                IntPtr(const_cast<uint8_t*>(match->data)),
                Data,
                0,
                match->data_length);
        }

        /// <summary>
        /// Read Data as a string. This will attempt to read as
        /// Unicode or ASCII but will not work correctly for binary Data.
        /// </summary>
        System::String^ AsString()
        {
            if (Data->Length == 0)
                return String::Empty;

            if (Data->Length > 1)
            {
                if (Data[0] == 0)
                    return Encoding::BigEndianUnicode->GetString(Data);

                else if (Data[1] == 0)
                    return Encoding::Unicode->GetString(Data);
            }

            return Encoding::ASCII->GetString(Data);
        }
    };
}
