#pragma once

#include <Windows.h>

class Stopwatch {
 public:
  Stopwatch() : m_timeBegin{ 0 }, m_timeEnd{ 0 }, m_isRunning( false ) {
    LARGE_INTEGER frequency;

    if ( !QueryPerformanceFrequency( &frequency ) ) {
      // log error
    }

    m_frequency = ( double )frequency.QuadPart;
  }

  void Start() {
    if ( !m_isRunning ) {
      QueryPerformanceCounter( &m_timeBegin );
      m_isRunning = true;
    }
  }

  void Stop() {
    if ( m_isRunning ) {
      QueryPerformanceCounter( &m_timeEnd );
      m_elapsedTime =
          ( m_timeEnd.QuadPart - m_timeBegin.QuadPart ) * 1000.0 / m_frequency;
      m_isRunning = false;
    }
  }

  void Restart() {
    Reset();
    Start();
  }

  void Reset() {
    m_isRunning = false;
    m_timeBegin.QuadPart = 0;
    m_timeEnd.QuadPart = 0;
    m_elapsedTime = 0;
  }

  double GetElapsedMilliseconds() {
    if ( m_isRunning ) {
      QueryPerformanceCounter( &m_timeEnd );
      return ( m_timeEnd.QuadPart - m_timeBegin.QuadPart ) * 1000.0 /
             m_frequency;
    }

    return m_elapsedTime;
  }

 private:
  LARGE_INTEGER m_timeBegin;
  LARGE_INTEGER m_timeEnd;
  double m_frequency;

  double m_elapsedTime;
  bool m_isRunning;
};