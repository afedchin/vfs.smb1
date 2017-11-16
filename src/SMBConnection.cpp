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

#include "SMBConnection.h"

#include <p8-platform/util/timeutils.h>

#include <kodi/Filesystem.h>
#include <kodi/General.h>
#include <kodi/Network.h>

extern "C"
{
#include <bdsm.h>
}

CSMBConnection& CSMBConnection::Get()
{
  static CSMBConnection instance;

  return instance;
}

CSMBConnection::CSMBConnection()
  : m_pSmbContext(nullptr)
  , m_hostName()
  , m_addr(0)
  , m_tid(0)
{
}

CSMBConnection::~CSMBConnection()
{
  smb_session_destroy(m_pSmbContext);
  m_pSmbContext = nullptr;
}

bool CSMBConnection::Connect(const VFSURL& url)
{
  P8PLATFORM::CLockObject lock(*this);

  smb_url* smburl = SMBParseUrl(url.url);
  netbios_ns* ns = netbios_ns_new();

  if (netbios_ns_resolve(ns, smburl->server, NETBIOS_FILESERVER, &m_addr))
    return false;

  if(m_hostName != url.hostname || m_pSmbContext)
  {
    m_pSmbContext = smb_session_new();
    if(!m_pSmbContext)
    {
      kodi::Log(ADDON_LOG_ERROR, "Failed to init SMB session");
      return false;
    }

    if (smb_session_connect(m_pSmbContext, smburl->server, m_addr, SMB_TRANSPORT_TCP) != DSM_SUCCESS)
    {
      kodi::Log(ADDON_LOG_ERROR, "Failed connected to %s", smburl->server);
      return false;
    }

    std::string domain = std::string(strlen(url.domain) > 0 ? url.domain : url.hostname);
    std::string username = std::string(strlen(url.username) > 0 ? url.username : "Guest"); // default NT user
    std::string password = std::string(strlen(url.password) > 0 ? url.password : "");

    smb_session_set_creds(m_pSmbContext, domain.c_str(), username.c_str(), password.c_str());
    if (smb_session_login(m_pSmbContext) != DSM_SUCCESS)
    {
      // try with default group
      smb_session_set_creds(m_pSmbContext, "WORKGROUP", username.c_str(), password.c_str());
      if (smb_session_login(m_pSmbContext) != DSM_SUCCESS)
      {
        return false;
      }
    }

    if (smb_session_is_guest(m_pSmbContext))
      kodi::Log(ADDON_LOG_DEBUG, "Login FAILED but we were logged in as GUEST to %s", smburl->server);
    else
      kodi::Log(ADDON_LOG_DEBUG, "Successfully logged in as %s\\%s to %s", smburl->domain, smburl->user, smburl->server);


    if (smb_tree_connect(m_pSmbContext, smburl->share, &m_tid) != DSM_SUCCESS)
    {
      kodi::Log(ADDON_LOG_ERROR, "Connect to share %s failed.", smburl->share);
      smb_session_destroy(m_pSmbContext);
      m_pSmbContext = nullptr;
      return false;
    }

    kodi::Log(ADDON_LOG_DEBUG,"SMB: Connected to server %s and share %s", url.hostname, smburl->share);
  }

  return true;
}

bool CSMBConnection::GetShares(const VFSURL & url, std::vector<kodi::vfs::CDirEntry>& items)
{
  uint32_t ip;
  smb_url* smburl = SMBParseUrl(url.url);
  netbios_ns* ns = netbios_ns_new();
  smb_session *session = nullptr;

  if (netbios_ns_resolve(ns, smburl->server, NETBIOS_FILESERVER, &ip))
  {
    goto failed;
  }

  session = smb_session_new();
  if (!session)
  {
    kodi::Log(ADDON_LOG_ERROR, "Failed to init SMB session");
    goto failed;
  }

  if (smb_session_connect(session, smburl->server, ip, SMB_TRANSPORT_TCP) != DSM_SUCCESS)
  {
    kodi::Log(ADDON_LOG_ERROR, "Failed connected to %s", smburl->server);
    goto failed;
  }

  smb_session_set_creds(session, smburl->domain, smburl->user, smburl->password);
  if (smb_session_login(session) != DSM_SUCCESS)
  {
    // try with default group
    smb_session_set_creds(session, "WORKGROUP", smburl->user, smburl->password);
    if (smb_session_login(session) != DSM_SUCCESS)
    {
      goto failed;
    }
  }

  if (smb_session_is_guest(session))
    kodi::Log(ADDON_LOG_DEBUG, "Login FAILED but we were logged in as GUEST to %s", smburl->server);
  else
    kodi::Log(ADDON_LOG_DEBUG, "Successfully logged in as %s\\%s to %s", smburl->domain, smburl->user, smburl->server);

  char **share_list;
  size_t share_count;
  if (smb_share_get_list(session, &share_list, &share_count) != DSM_SUCCESS)
  {
    kodi::Log(ADDON_LOG_DEBUG, "Failed to get share list from %s", smburl->server);
    goto failed;
  }

  for (size_t i = 0; i < share_count; i++)
  {
    std::string path(std::string(url.url) + std::string(share_list[i]));

    kodi::vfs::CDirEntry pItem;
    pItem.SetLabel(share_list[i]);
    if (path[path.size() - 1] != '/')
      path += '/';
    pItem.SetFolder(true);

    if (share_list[i][0] == '.')
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
  smb_share_list_destroy(share_list);
  smb_session_destroy(session);
  netbios_ns_destroy(ns);

  return true;

failed:
  if (ns)
    netbios_ns_destroy(ns);
  if (session)
    smb_session_destroy(session);

  return false;
}

struct smb_url * CSMBConnection::SMBParseUrl(const char *url)
{
  struct smb_url *u;
  char *ptr, *tmp, str[MAX_URL_SIZE];

  if (strncmp(url, "smb://", 6)) {
    return NULL;
  }
  if (strlen(url + 6) >= MAX_URL_SIZE) {
    return NULL;
  }
  strncpy(str, url + 6, MAX_URL_SIZE);

  u = (smb_url *)malloc(sizeof(struct smb_url));
  if (u == NULL) {
    return NULL;
  }
  memset(u, 0, sizeof(struct smb_url));

  ptr = str;

  /* domain */
  if ((tmp = strchr(ptr, ';')) != NULL) {
    *(tmp++) = '\0';
    u->domain = strdup(ptr);
    ptr = tmp;
  }
  /* user */
  if ((tmp = strchr(ptr, '@')) != NULL) {
    *(tmp++) = '\0';
    u->user = strdup(ptr);
    ptr = tmp;
  }
  /* password */
  if ((tmp = strchr(ptr, ':')) != NULL) {
    *(tmp++) = '\0';
    u->password = strdup(ptr);
    ptr = tmp;
  }
  /* server */
  if ((tmp = strchr(ptr, '/')) != NULL) {
    *(tmp++) = '\0';
    u->server = strdup(ptr);
    ptr = tmp;
  }

  /* Do we just have a share or do we have both a share and an object */
  tmp = strchr(ptr, '/');

  /* We only have a share */
  if (tmp == NULL) {
    u->share = strdup(ptr);
    return u;
  }

  /* we have both share and object path */
  *(tmp++) = '\0';
  u->share = strdup(ptr);
  u->path = strdup(tmp);

  return u;
}