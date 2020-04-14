#pragma once

#include <iostream>

namespace __privadad {

template <typename F>
struct Defer {
  Defer( F f ) : func_( f ) {}

  ~Defer() {
    func_();
  }

  F func_;
};

// CHAOS
#define __Defer2( code, county ) \
  __privadad::Defer __defer##county( [&]() { code; } );

#define __Defer1( code, county ) __Defer2( code, county )

#define Defer( code ) __Defer1( code, __COUNTER__ )

}  // namespace __privadad