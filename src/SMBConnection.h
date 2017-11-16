
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

#define MAX_URL_SIZE 2048

struct smb_url 
{
  const char *domain;
  const char *user;
  const char *password;
  const char *server;
  const char *share;
  const char *path;
};

struct smb_session;

class CSMBConnection : public P8PLATFORM::CMutex
{
public:
  static CSMBConnection& Get();
  virtual ~CSMBConnection();
  bool Connect(const VFSURL& url);
  struct smb_session *GetSmbContext() { return m_pSmbContext; }
  uint16_t GetTreeId() { return m_tid; }

  static bool CSMBConnection::GetShares(const VFSURL& url, std::vector<kodi::vfs::CDirEntry>& items);
  static smb_url *CSMBConnection::SMBParseUrl(const char *url);

private:
  CSMBConnection();
  struct smb_session *m_pSmbContext;

  std::string m_hostName;
  uint32_t m_addr;
  uint16_t m_tid;
};
