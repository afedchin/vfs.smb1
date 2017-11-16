
/*
 *      Copyright (C) 2005-2013 Team XBMC
 *      http://xbmc.org
 *
 *  This Program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This Program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with XBMC; see the file COPYING.  If not, see
 *  <http://www.gnu.org/licenses/>.
 *
 */

#include <list>
#include <map>
#include <stdint.h>
#include <string>

#include <kodi/addon-instance/VFS.h>
#include <p8-platform/threads/mutex.h>

struct netbios_ns;
struct netbios_ns_entry;

class CNBConnection : public P8PLATFORM::CMutex
{
public:
  static CNBConnection& Get();
  virtual ~CNBConnection();
  bool Start();
  bool Stop();
  struct netbios_ns *GetNBContext(){ return m_pNbContext; }

  void OnEntryAdded(netbios_ns_entry *entry);
  void OnEntryRemoved(netbios_ns_entry *entry);

  void GetDirectory(const VFSURL& url, std::vector<kodi::vfs::CDirEntry>& items);

private:
  struct hetbios_host
  {
    char type;
    uint32_t ip;
    std::string name;
    std::string domain;
  };

  CNBConnection();
  struct netbios_ns *m_pNbContext;
  std::vector<hetbios_host> m_hosts;

  std::string resolveHost(const std::string& hostname);
};
