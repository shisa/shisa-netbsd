// 2004-11-29  Paolo Carlini  <pcarlini@suse.de>

// Copyright (C) 2004 Free Software Foundation
//
// This file is part of the GNU ISO C++ Library.  This library is free
// software; you can redistribute it and/or modify it under the
// terms of the GNU General Public License as published by the
// Free Software Foundation; either version 2, or (at your option)
// any later version.

// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License along
// with this library; see the file COPYING.  If not, write to the Free
// Software Foundation, 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
// USA.

// 21.3.3 string capacity

#include <string>
#include <testsuite_hooks.h>

// libstdc++/18654
void test01()
{
  using namespace std;
  bool test __attribute__((unused)) = true;

  typedef string::size_type size_type;

  // Our current implementation provides exact shrink-to-size
  // and shrink-to-fit (in the future, maybe this will change
  // for short strings).
  const size_type minsize = 2 << 0;
  const size_type maxsize = 2 << 20;
  for (size_type i = minsize; i <= maxsize; i *= 2)
    {
      string str(i, 'x');
      str.reserve(3 * i);

      str.reserve(2 * i);
      VERIFY( str.capacity() == 2 * i );

      str.reserve();
      VERIFY( str.capacity() == i );
    }
}

int main()
{
  test01();
  return 0;
}
