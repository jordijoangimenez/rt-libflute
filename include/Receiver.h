// libflute - FLUTE/ALC library
//
// Copyright (C) 2021 Klaus Kühnhammer (Österreichische Rundfunksender GmbH & Co KG)
//
// Licensed under the License terms and conditions for use, reproduction, and
// distribution of 5G-MAG software (the “License”).  You may not use this file
// except in compliance with the License.  You may obtain a copy of the License at
// https://www.5g-mag.com/reference-tools.  Unless required by applicable law or
// agreed to in writing, software distributed under the License is distributed on
// an “AS IS” BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied.
//
// See the License for the specific language governing permissions and limitations
// under the License.
//
#pragma once
#include <boost/asio.hpp>
#include <boost/bind/bind.hpp>
#include <string>
#include <map>
#include <mutex>
#include "File.h"
#include "FileDeliveryTable.h"

namespace LibFlute {
  /**
   *  FLUTE receiver class. Construct an instance of this to receive files from a FLUTE/ALC session.
   */
  class Receiver {
    public:
     /**
      *  Definition of a file reception completion callback function that can be
      *  registered through ::register_completion_callback.
      *
      *  @returns shared_ptr to the received file
      */
      typedef std::function<void(std::shared_ptr<LibFlute::File>)> completion_callback_t;
     /**
      *  Default constructor.
      *
      *  @param iface Address of the (local) interface to bind the receiving socket to. 0.0.0.0 = any.
      *  @param address Multicast address
      *  @param port Target port
      *  @param tsi TSI value of the session
      *  @param io_context Boost io_context to run the socket operations in (must be provided by the caller)
      */
      Receiver( const std::string& iface, const std::string& address,
          short port, uint64_t tsi,
          boost::asio::io_context& io_context);

     /**
      *  Default destructor.
      */
      virtual ~Receiver() = default;

     /**
      *  Enable IPSEC ESP decryption of FLUTE payloads.
      *
      *  @param spi Security Parameter Index value to use
      *  @param key AES key as a hex string (without leading 0x). Must be an even number of characters long.
      */
      void enable_ipsec( uint32_t spi, const std::string& aes_key);

     /**
      *  List all current files
      *
      *  @return Vector of all files currently in the FDT
      */
      std::vector<std::shared_ptr<LibFlute::File>> file_list();

     /**
      *  Remove files from the list that are older than max_age seconds
      */
      void remove_expired_files(unsigned max_age);

     /**
      *  Remove a file from the list that matches the passed content location
      */
      void remove_file_with_content_location(const std::string& cl);

     /**
      *  Register a callback for file reception notifications
      *
      *  @param cb Function to call on file completion
      */
      void register_completion_callback(completion_callback_t cb) { _completion_cb = cb; };

      void stop() { _running = false; }
    private:

      void handle_receive_from(const boost::system::error_code& error,
          size_t bytes_recvd);
      boost::asio::ip::udp::socket _socket;
      boost::asio::ip::udp::endpoint _sender_endpoint;

      // Must hold the largest UDP datagram that can actually arrive: with the
      // Compact No-Code FEC scheme, a packet is a 4-byte SBN+ID header plus one
      // full encoding symbol, and FEC-OTI-Encoding-Symbol-Length is a per-session
      // configuration value with no fixed small upper bound (e.g. large symbols
      // sized close to the path MTU, or, as over loopback/jumbo-capable links,
      // sized close to the max IPv4 UDP payload). A too-small buffer here doesn't
      // error out -- recvfrom() on a datagram socket silently truncates to
      // whatever fits, so every symbol beyond that size is completed with
      // whatever partial prefix arrived, and the truncation is invisible until a
      // Content-MD5 check (if present in the FDT) catches the corruption. 65536
      // covers the maximum possible IPv4 UDP payload (65507 bytes) with margin.
      enum { max_length = 65536 };
      char _data[max_length];
      uint64_t _tsi;
      std::unique_ptr<LibFlute::FileDeliveryTable> _fdt;
      // FDT instance currently being reassembled at TOI 0 (0xFFFFFFFF = none).
      // Used to discard a partial FDT object when a newer instance starts
      // arriving, so two instances never splice into one corrupt buffer.
      uint32_t _fdt_in_progress_instance_id = 0xFFFFFFFF;
      std::map<uint64_t, std::shared_ptr<LibFlute::File>> _files;
      std::mutex _files_mutex;
      std::string _mcast_address;

      completion_callback_t _completion_cb = nullptr;

      bool _running = true;
  };
};
