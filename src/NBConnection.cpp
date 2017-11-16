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

#include "NBConnection.h"

#include <p8-platform/util/timeutils.h>

#include <kodi/Filesystem.h>
#include <kodi/General.h>
#include <kodi/Network.h>

#include <algorithm>

extern "C"
{
#include <bdsm.h>
}

static void on_entry_added(void *p_opaque, netbios_ns_entry *entry)
{
  auto nb_conn = reinterpret_cast<CNBConnection*>(p_opaque);
  P8PLATFORM::CLockObject lock(*nb_conn);

  nb_conn->OnEntryAdded(entry);
}

static void on_entry_removed(void *p_opaque, netbios_ns_entry *entry)
{
  auto nb_conn = reinterpret_cast<CNBConnection*>(p_opaque);
  P8PLATFORM::CLockObject lock(*nb_conn);

  nb_conn->OnEntryRemoved(entry);
}

CNBConnection& CNBConnection::Get()
{
  static CNBConnection instance;

  return instance;
}

CNBConnection::CNBConnection()
: m_pNbContext(nullptr)
{
}

CNBConnection::~CNBConnection()
{
  netbios_ns_destroy(m_pNbContext);

  m_pNbContext = nullptr;
}

std::string CNBConnection::resolveHost(const std::string& hostname)
{
  std::string resolvedName;
  kodi::network::DNSLookup(hostname, resolvedName);
  return resolvedName;
}

bool CNBConnection::Start()
{
  P8PLATFORM::CLockObject lock(*this);

  if(!m_pNbContext)
  {
    netbios_ns_discover_callbacks callbacks;
    callbacks.p_opaque = (void*)this;
    callbacks.pf_on_entry_added = on_entry_added;
    callbacks.pf_on_entry_removed = on_entry_removed;

    m_pNbContext = netbios_ns_new();
    if(!m_pNbContext)
    {
      kodi::Log(ADDON_LOG_ERROR, "Failed to init NetBios context");
      return false;
    }

    kodi::Log(ADDON_LOG_DEBUG, "Starting discovering network");

    if (netbios_ns_discover_start(m_pNbContext, 
                                  10, // broadcast every 10 seconds
                                  &callbacks))
    {
      kodi::Log(ADDON_LOG_ERROR, "Error while discovering local network");
      netbios_ns_destroy(m_pNbContext);
      m_pNbContext = nullptr;
      return false;
    }
  }

  return true;
}

bool CNBConnection::Stop()
{
  P8PLATFORM::CLockObject lock(*this);
  if (m_pNbContext)
  {
    return netbios_ns_discover_stop(m_pNbContext) == 0;
  }
  return false;
}

void CNBConnection::OnEntryAdded(netbios_ns_entry * entry)
{
  uint32_t ip = netbios_ns_entry_ip(entry);
  struct in_addr addr;
  addr.s_addr = ip;

  auto it = std::find_if(m_hosts.begin(), m_hosts.end(), [ip](const hetbios_host& host) {
    return ip == host.ip;
  });

  if (it == m_hosts.end())
  {
    hetbios_host host;
    host.ip = ip;
    host.type = netbios_ns_entry_type(entry);
    host.domain = std::string(netbios_ns_entry_group(entry));
    host.name = std::string(netbios_ns_entry_name(entry));

    m_hosts.push_back(host);

    kodi::Log(ADDON_LOG_DEBUG, "OnEntryAdded >>> Ip:%s name: %s/%s",
      inet_ntoa(addr),
      host.domain.c_str(),
      host.name.c_str());
  }
  else
  {
    // need update?
    it->type = netbios_ns_entry_type(entry);
    it->domain = std::string(netbios_ns_entry_group(entry));
    it->name = std::string(netbios_ns_entry_name(entry));
  }
}

void CNBConnection::OnEntryRemoved(netbios_ns_entry * entry)
{
  uint32_t ip = netbios_ns_entry_ip(entry);

  auto it = std::find_if(m_hosts.begin(), m_hosts.end(), [ip](const hetbios_host& host) {
    return ip == host.ip;
  });

  if (it != m_hosts.end())
  {
    struct in_addr addr;
    addr.s_addr = it->ip;

    kodi::Log(ADDON_LOG_DEBUG, "OnEntryRemoved >>> Ip:%s name: %s/%s", 
      inet_ntoa(addr),
      it->domain.c_str(), 
      it->name.c_str());

    m_hosts.erase(it);
  }
}

void CNBConnection::GetDirectory(const VFSURL& url, std::vector<kodi::vfs::CDirEntry>& items)
{
  P8PLATFORM::CLockObject lock(*this);

  for (hetbios_host& host : m_hosts)
  {
    std::string path(std::string(url.url) + std::string(host.name));

    kodi::vfs::CDirEntry pItem;
    pItem.SetLabel(host.name);
    if (path[path.size() - 1] != '/')
      path += '/';
    pItem.SetFolder(true);

    if (host.name[0] == '.')
    {
      pItem.AddProperty("file:hidden", "true");
    }
    else
    {
      pItem.ClearProperties();
    }

    pItem.SetPath(path);
    items.push_back(pItem);
  }
}
