#include <iostream>
#include <thread>
#include <Windows.h>
#include <vector>

#define NOINLINE __declspec( noinline )

CRITICAL_SECTION crit_section;

NOINLINE int ReturnValue() {
  // EnterCriticalSection(&crit_section);
  // int test = 1337;
  // LeaveCriticalSection(&crit_section);
  return 1337;
}

NOINLINE int SumValues( int val1, int val2 ) {
  return val1 + val2;
}

NOINLINE void main3() {
  while ( true ) {
    // EnterCriticalSection(&crit_section);
    printf( "3: %d", ReturnValue() );
    // LeaveCriticalSection(&crit_section);
  }
}

NOINLINE void main2() {
  while ( true ) {
    // EnterCriticalSection(&crit_section);
    printf( "2: %d", ReturnValue() );
    // LeaveCriticalSection(&crit_section);
  }
}

class CPolygon {
 protected:
  int width, height;

 public:
  void set_values( int a, int b ) {
    width = a;
    height = b;
  }

  virtual void NewMain() {
    while ( true ) {
      printf( "1 (ReturnValueBase): %d", ReturnValue() );
      printf( "1 (SumValuesBase): %d", SumValues( 5, 15 ) );
    }
  }
};

class Circle : public CPolygon {
 public:
  int area() {
    return width * height;
  }

  virtual void NewMain() {
    int value;
    std::cin >> value;

    switch ( value ) {
      case 0:
        printf( "0" );
        break;
      case 1:
        printf( "1" );
        break;
      case 2:
        printf( "2" );
      case 3:
        printf( "3" );
      case 4:
        printf( "4" );
      case 5:
        printf( "5" );
      case 6:
        printf( "6" );
      case 7:
        printf( "7" );
      case 8:
        printf( "8" );
      default:
        break;
    }

    std::thread t( main2 );
    t.detach();

    for ( int i = 0; i < 100; ++i ) {
      std::thread t2( main3 );
      t2.detach();
    }

    while ( true ) {
      printf( "1 (ReturnValueCircle): %d", ReturnValue() );
      printf( "1 (SumValuesCircle): %d", SumValues( 5, 15 ) );
    }

    std::cin.get();
  }
};

class CRectangle : public CPolygon {
 public:
  int area() {
    return width * height;
  }

  virtual void NewMain() {
    int value;
    std::cin >> value;

    switch ( value ) {
      case 0:
        printf( "0" );
        break;
      case 1:
        printf( "1" );
        break;
      case 2:
        printf( "2" );
      case 3:
        printf( "3" );
      case 4:
        printf( "4" );
      case 5:
        printf( "5" );
      case 6:
        printf( "6" );
      case 7:
        printf( "7" );
      case 8:
        printf( "8" );
      default:
        break;
    }

    std::thread t( main2 );
    t.detach();

    for ( int i = 0; i < 100; ++i ) {
      std::thread t2( main3 );
      t2.detach();
    }

    while ( true ) {
      printf( "1 (ReturnValueRectangle): %d", ReturnValue() );
      printf( "1 (SumValuesRectangle): %d", SumValues( 5, 15 ) );
    }

    std::cin.get();
  }
};

class Triangle : public CPolygon {
 public:
  int area() {
    return width * height / 2;
  }

  virtual void NewMain() {
    int value;
    std::cin >> value;

    switch ( value ) {
      case 0:
        printf( "0" );
        break;
      case 1:
        printf( "1" );
        break;
      case 2:
        printf( "2" );
      case 3:
        printf( "3" );
      case 4:
        printf( "4" );
      case 5:
        printf( "5" );
      case 6:
        printf( "6" );
      case 7:
        printf( "7" );
      case 8:
        printf( "8" );
      default:
        break;
    }

    std::thread t( main2 );
    t.detach();

    for ( int i = 0; i < 100; ++i ) {
      std::thread t2( main3 );
      t2.detach();
    }

    while ( true ) {
      printf( "1 (ReturnValueG): %d", ReturnValue() );
      printf( "1 (SumValuesG): %d", SumValues( 5, 15 ) );
    }

    std::cin.get();
  }
};

class NeuzBase {
 public:
  NeuzBase() {}
  ~NeuzBase() {}

  virtual int Run() {
    int res = Render();
    return res;
  }

 protected:
  virtual HRESULT Render() {
    return S_OK;
  }
};

class Neuz : public NeuzBase {
 public:
  Neuz() {}
  ~Neuz() {}

 protected:
  HRESULT Render() {
    printf( "DICKDICKDICK" );
    return S_OK;
  }
};

Neuz g_neuz;

/*
__declspec( dllexport )
    IMAGE_NT_HEADERS* GetNtHeaders( uintptr_t region_base ) {
  auto dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>( region_base );

  auto nt_headers =
      reinterpret_cast<IMAGE_NT_HEADERS*>( region_base + dos_header->e_lfanew );

  return nt_headers;
}
*/

int main() {
  static std::vector<int> test_static_tls_data_temp_var = {
    1338, 1338, 1338, 1338, 1338, 1338, 1338, 1338, 1338, 1338, 1338,
    1338, 1338, 1338, 1338, 1338, 1338, 1338, 1338, 1338, 1338, 1338,
    1338, 1338, 1338, 1338, 1338, 1338, 1338, 1338, 1338, 1338, 1338,
  };

  // If the static tls initialization call above does not work properly, inform us about that shits
  //
  if ( test_static_tls_data_temp_var.size() == 0 ) {
    MessageBox( 0,
                TEXT( "Static tls data is not working properly, have you "
                      "initialized it?" ),
                TEXT( "ds" ), 0 );

    return -1;
  }

  static std::vector<int> test_static_tls_data_temp_var2 = {
    1337, 1337, 1337, 1337, 1337, 1337, 1337, 1337, 1337, 1337,
    1337, 1337, 1337, 1337, 1337, 1337, 1337, 1337, 1337, 1337,
    1337, 1337, 1337, 1337, 1337, 1337, 1337, 1337, 1337, 1337,
    1337, 1337, 1337, 1337, 1337, 1337, 1337, 1337, 1337
  };

  // If the static tls initialization call above does not work properly, inform us about that shits
  //
  if ( test_static_tls_data_temp_var2.size() == 0 ) {
    MessageBox( 0,
                TEXT( "Static tls data is not working properly, have you "
                      "initialized it?" ),
                TEXT( "ds" ), 0 );

    return -1;
  }

  static std::vector<int> test_static_tls_data_temp_var3 = {
    1339, 1339, 1339, 1339, 1339, 1339, 1339, 1339, 1339, 1339, 1339,
    1339, 1339, 1339, 1339, 1339, 1339, 1339, 1339, 1339, 1339, 1339,
    1339, 1339, 1339, 1339, 1339, 1339, 1339, 1339, 1339,
  };

  // If the static tls initialization call above does not work properly, inform us about that shits
  //
  if ( test_static_tls_data_temp_var3.size() == 0 ) {
    MessageBox( 0,
                TEXT( "Static tls data is not working properly, have you "
                      "initialized it?" ),
                TEXT( "ds" ), 0 );

    return -1;
  }

  for ( auto lol : test_static_tls_data_temp_var ) {
    std::cout << lol << std::endl;
  }

  for ( auto lol : test_static_tls_data_temp_var2 ) {
    std::cout << lol << std::endl;
  }

  for ( auto lol : test_static_tls_data_temp_var3 ) {
    std::cout << lol << std::endl;
  }

  /*
  auto lol = GetModuleHandle( 0 );
  const auto nt_headers = GetNtHeaders( reinterpret_cast<uintptr_t>( lol ) );

  DWORD old;
  VirtualProtect( lol, 1024, PAGE_READWRITE, &old );

  // NULLIFY THE IMPORT DIRECTORY WHEN A USER IS DUMPING TO REMOVE IMPORTS
  nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ]
      .Size = 0;
  nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ]
      .VirtualAddress = 0;
  */

  MessageBoxA( 0, "Test123123", "dasdas", 0 );

  printf( "Beginning!" );

  g_neuz.Run();

  std::vector<CPolygon*> polygons;
  polygons.push_back( new Triangle );
  polygons.push_back( new Circle );
  polygons.push_back( new CRectangle );

  for ( int i = 3; i < 10; ++i ) {
    polygons.push_back( new Circle );
  }

  for ( int i = 0; i < 10; ++i ) {
    polygons[ i ]->NewMain();
  }

  // CPolygon *base = new Triangle;
  // base->NewMain();

  MessageBoxA( 0, "Test", "dasdas", 0 );

  printf( "Ending!" );

  return 0;
}