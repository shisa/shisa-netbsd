//
// Automated Testing Framework (atf)
//
// Copyright (c) 2007 The NetBSD Foundation, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. All advertising materials mentioning features or use of this
//    software must display the following acknowledgement:
//        This product includes software developed by the NetBSD
//        Foundation, Inc. and its contributors.
// 4. Neither the name of The NetBSD Foundation nor the names of its
//    contributors may be used to endorse or promote products derived
//    from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND
// CONTRIBUTORS ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
// INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
// IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
// GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
// IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
// IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

#include "config.h"

#include <cstdarg>
#include <cstdio>
#include <cstring>

#include "atf/exceptions.hpp"

#if !defined(HAVE_VSNPRINTF_IN_STD)
namespace std {
using ::vsnprintf;
}
#endif // !defined(HAVE_VSNPRINTF_IN_STD)

atf::system_error::system_error(const std::string& who,
                                const std::string& message,
                                int sys_err) :
    std::runtime_error(who + ": " + message),
    m_sys_err(sys_err)
{
}

atf::system_error::~system_error(void)
    throw()
{
}

int
atf::system_error::code(void)
    const
    throw()
{
    return m_sys_err;
}

const char*
atf::system_error::what(void)
    const
    throw()
{
    try {
        if (m_message.length() == 0) {
            m_message = std::string(std::runtime_error::what()) + ": ";
            m_message += ::strerror(m_sys_err);
        }

        return m_message.c_str();
    } catch (...) {
        return "Unable to format system_error message";
    }
}

atf::usage_error::usage_error(const char *fmt, ...)
    throw() :
    std::runtime_error("usage_error; message unformatted")
{
    va_list ap;

    va_start(ap, fmt);
    std::vsnprintf(m_text, sizeof(m_text), fmt, ap);
    va_end(ap);
}

atf::usage_error::~usage_error(void)
    throw()
{
}

const char*
atf::usage_error::what(void)
    const throw()
{
    return m_text;
}
