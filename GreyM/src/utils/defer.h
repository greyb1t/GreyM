#pragma once

namespace __privadad {

template <typename F>
struct Defer {
  Defer( F f ) : func_( f ) {}

  ~Defer() {
    func_();
  }

  F func_;
};

template <typename F>
Defer<F> __DeferFunc( F f ) {
  return Defer<F>( f );
}

// CHAOS
#define __Defer2( code, county ) \
  const auto __defer##county = __privadad::__DeferFunc( [&]() { code; } )

#define __Defer1( code, county ) __Defer2( code, county )

#define Defer( code ) __Defer1( code, __COUNTER__ )

}  // namespace __privadad
