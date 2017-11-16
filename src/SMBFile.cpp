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

#include "p8-platform/threads/mutex.h"
#include <fcntl.h>
#include <inttypes.h>
#include <sstream>
#include <iostream>
#include <algorithm>

extern "C"
{
#include <bdsm.h>
}

#include "SMBFile.h"
#include "NBConnection.h"

CSMBFile::CSMBFile(KODI_HANDLE instance) 
  : CInstanceVFS(instance) 
{
  CNBConnection::Get().Start();
}

CSMBFile::~CSMBFile()
{
  CNBConnection::Get().Stop();
}

void* CSMBFile::Open(const VFSURL& url)
{
  int ret = 0;
  P8PLATFORM::CLockObject lock(CSMBConnection::Get());

  smb_url *smburl = nullptr;
  smburl = CSMBConnection::SMBParseUrl(url.url);

  if(!CSMBConnection::Get().Connect(url))
  {
    return nullptr;
  }

  SMBContext* result = new SMBContext;
  result->pSession = CSMBConnection::Get().GetSmbContext();
  std::string path = std::string(smburl->path);
  std::replace(path.begin(), path.end(), '/', '\\'); // to native path

  if (smb_fopen(result->pSession, CSMBConnection::Get().GetTreeId(), path.c_str(),
                O_RDONLY, &result->pFileHandle) != DSM_SUCCESS)
  {
    kodi::Log(ADDON_LOG_INFO, "CSMBFile::Open: Unable to open file : '%s'  error : '%d'", smburl->path, smb_session_get_nt_status(result->pSession));
    delete result;
    return nullptr;
  }

  if (!result->pFileHandle)
  {
    kodi::Log(ADDON_LOG_INFO, "CSMBFile::Open: Unable to open file : '%s'  error : '%d'", smburl->path, smb_session_get_nt_status(result->pSession));
    delete result;
    return nullptr;
  }

  kodi::Log(ADDON_LOG_DEBUG,"CSMBFile::Open - opened %s", smburl->path);
  result->filename = smburl->path;

  struct __stat64 tmpBuffer;

  if( Stat(url, &tmpBuffer) )
  {
    Close(result);
    return nullptr;
  }

  result->size = tmpBuffer.st_size;
  // We've successfully opened the file!*/
  return result;
}

ssize_t CSMBFile::Read(void* context, void* lpBuf, size_t uiBufSize)
{
  SMBContext* ctx = (SMBContext*)context;
  if (!ctx || !ctx->pFileHandle|| !ctx->pSession)
    return -1;

  P8PLATFORM::CLockObject lock(CSMBConnection::Get());
  ssize_t numberOfBytesRead = smb_fread(ctx->pSession, ctx->pFileHandle, lpBuf, uiBufSize);

  //something went wrong ...
  if (numberOfBytesRead < 0)
    kodi::Log(ADDON_LOG_ERROR, "%s - Error( %" PRId64", %s )", __FUNCTION__, (int64_t)numberOfBytesRead
                              , smb_session_get_nt_status(ctx->pSession));

  return numberOfBytesRead;
}

int64_t CSMBFile::Seek(void* context, int64_t iFilePosition, int iWhence)
{
  SMBContext* ctx = (SMBContext*)context;
  if (!ctx || !ctx->pFileHandle|| !ctx->pSession)
    return 0;

  int64_t ret = 0;
  uint64_t offset = 0;

  P8PLATFORM::CLockObject lock(CSMBConnection::Get());

  ret = smb_fseek(ctx->pSession, ctx->pFileHandle, iFilePosition, iWhence);
  if (ret < 0)
  {
    kodi::Log(ADDON_LOG_ERROR, "%s - Error( seekpos: %" PRId64 ", whence: %i, fsize: %" PRId64 ", %d)",
              __FUNCTION__, iFilePosition, iWhence, ctx->size, smb_session_get_nt_status(ctx->pSession));
    return -1;
  }
  return ret;
}

int64_t CSMBFile::GetLength(void* context)
{
  if (!context)
    return 0;

  SMBContext* ctx = (SMBContext*)context;
  return ctx->size;
}

int64_t CSMBFile::GetPosition(void* context)
{
  if (!context)
    return 0;

  SMBContext* ctx = (SMBContext*)context;
  int64_t ret = 0;
  uint64_t offset = 0;

  if (CSMBConnection::Get().GetSmbContext() == nullptr || !ctx->pFileHandle)
    return 0;

  P8PLATFORM::CLockObject lock(CSMBConnection::Get());
  ret = smb_fseek(CSMBConnection::Get().GetSmbContext(), ctx->pFileHandle, offset, SMB_SEEK_CUR);
  if (ret < 0)
  {
    kodi::Log(ADDON_LOG_ERROR, "SMB: Failed to lseek(%d)", smb_session_get_nt_status(CSMBConnection::Get().GetSmbContext()));
  }
  return ret;
}

int CSMBFile::IoControl(void* context, XFILE::EIoControl request, void* param)
{
  if(request == XFILE::IOCTRL_SEEK_POSSIBLE)
    return 1;

  return -1;
}

int CSMBFile::Stat(const VFSURL& url, struct __stat64* buffer)
{
  P8PLATFORM::CLockObject lock(CSMBConnection::Get());

  smb_url *smburl = nullptr;
  smburl = CSMBConnection::SMBParseUrl(url.url);

  if (!CSMBConnection::Get().Connect(url))
  {
    return 0;
  }

  smb_fd fd;
  smb_session* session = CSMBConnection::Get().GetSmbContext();
  std::string path = std::string(smburl->path);
  std::replace(path.begin(), path.end(), '/', '\\'); // to native path

  if (smb_fopen(session, CSMBConnection::Get().GetTreeId(), path.c_str(), O_RDONLY, &fd) != DSM_SUCCESS)
  {
    kodi::Log(ADDON_LOG_INFO, "CSMBFile::Open: Unable to open file : '%s'  error : '%d'", smburl->path, smb_session_get_nt_status(session));
    return -1;
  }

  if (!fd)
  {
    kodi::Log(ADDON_LOG_INFO, "CSMBFile::Open: Unable to open file : '%s'  error : '%d'", smburl->path, smb_session_get_nt_status(session));
    return -1;
  }

  smb_stat st = smb_stat_fd(session, fd);
  if (!st)
  {
    kodi::Log(ADDON_LOG_ERROR, "SMB: Failed to stat(%s) %d", url.filename, smb_session_get_nt_status(session));
    return -1;
  }

  if (buffer != nullptr)
  {
    memset(buffer, 0, sizeof(struct __stat64));
    buffer->st_ino = 0; //smb_stat_get(st, ??);
    buffer->st_nlink = 0; //smb_stat_get(st, ??);
    buffer->st_size = smb_stat_get(st, SMB_STAT_SIZE);
    buffer->st_atime = smb_stat_get(st, SMB_STAT_ATIME);
    buffer->st_mtime = smb_stat_get(st, SMB_STAT_MTIME);
    buffer->st_ctime = smb_stat_get(st, SMB_STAT_CTIME);
  }
  else
  {
    //if buffer == nullptr we where called from Exists - in that case we close file handle
    smb_fclose(session, fd);
  }

  return 0;
}

bool CSMBFile::Close(void* context)
{
  SMBContext* ctx = (SMBContext*)context;
  if (!ctx)
    return false;

  P8PLATFORM::CLockObject lock(CSMBConnection::Get());

  if (ctx->pFileHandle && ctx->pSession != nullptr)
  {
    kodi::Log(ADDON_LOG_DEBUG,"CSMBFile::Close closing file %s", ctx->filename.c_str());
    smb_fclose(ctx->pSession, ctx->pFileHandle);
  }

  delete ctx;
  return true;
}

bool CSMBFile::Exists(const VFSURL& url)
{
  return Stat(url, nullptr) == 0;
}

bool CSMBFile::GetDirectory(const VFSURL& url, std::vector<kodi::vfs::CDirEntry>& items, CVFSCallbacks callbacks)
{
  P8PLATFORM::CLockObject lock(CSMBConnection::Get());
  netbios_ns* ns = nullptr;
  smb_session *session = nullptr;
  smb_url *smburl = nullptr;

  smburl = CSMBConnection::SMBParseUrl(url.url);
  if (!smburl)
  {
    kodi::Log(ADDON_LOG_ERROR, "Failed to parse url: %s", url.url);
    return false;
  }

  std::string domain = std::string(strlen(url.domain) > 0 ? url.domain : url.hostname);
  std::string username = std::string(strlen(url.username) > 0 ? url.username : "Guest"); // default NT user
  std::string password = std::string(strlen(url.password) > 0 ? url.password : "");

  if (strlen(url.hostname) == 0)
  {
    // browse entire a network
    CNBConnection::Get().GetDirectory(url, items);
  }
  else if (strlen(url.sharename) == 0)
  {
    // browse shares on a server
    uint32_t ip;

    ns = netbios_ns_new();
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

    smb_session_set_creds(session, domain.c_str(), username.c_str(), password.c_str());
    if (smb_session_login(session) != DSM_SUCCESS)
    {
      // try with default group
      smb_session_set_creds(session, "WORKGROUP", url.username, url.password);
      if (smb_session_login(session) != DSM_SUCCESS)
      {
        // try with server guest
        smb_session_set_creds(session, url.hostname, "Guest", "");
        if (smb_session_login(session) != DSM_SUCCESS)
        {
          callbacks.RequireAuthentication(url.url);
          goto failed;
        }
      }
    }

    if (smb_session_is_guest(session))
      kodi::Log(ADDON_LOG_DEBUG, "Login FAILED but we were logged in as GUEST to %s", smburl->server);
    else
      kodi::Log(ADDON_LOG_DEBUG, "Successfully logged in as %s\\%s to %s", domain.c_str(), username.c_str(), url.hostname);

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
      std::string shareName = std::string(share_list[i]);

      kodi::vfs::CDirEntry pItem;
      pItem.SetLabel(shareName);

      if (path[path.size() - 1] != '/')
        path += '/';
      pItem.SetFolder(true);

      if (shareName[0] == '.' 
        || shareName[shareName.size() - 1] == '$')
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
  else
  {
    if (!CSMBConnection::Get().Connect(url))
    {
      return false;
    }

    smb_session* session = CSMBConnection::Get().GetSmbContext();
    smb_tid tid = CSMBConnection::Get().GetTreeId();
    smb_file *files = nullptr;
    smb_stat st;

    std::string path = std::string(smburl->path);
    std::replace(path.begin(), path.end(), '/', '\\'); // to native path

    if (path[path.size() - 1] == '\\')
      path += '*';
    else
      path += "\\*";

    files = smb_find(session, tid, path.c_str());
    size_t files_count = smb_stat_list_count(files);
    for (size_t i = 0; i < files_count; i++)
    {
      st = smb_stat_list_at(files, i);
      if (st == nullptr)
        goto failed;

      std::string file_name(smb_stat_name(st));
      // skip parents
      if (file_name == "." || file_name == "..")
        continue;

      bool isDir = smb_stat_get(st, SMB_STAT_ISDIR) > 0;
      std::string item_path(std::string(url.url) + file_name);

      kodi::vfs::CDirEntry pItem;
      pItem.SetLabel(file_name);

      if (isDir)
      {
        if (item_path[item_path.size() - 1] != '/')
          item_path += '/';
        pItem.SetFolder(true);
      }
      else
      {
        pItem.SetSize(smb_stat_get(st, SMB_STAT_SIZE));
        pItem.SetFolder(false);
      }

      if (file_name[0] == '.')
      {
        pItem.AddProperty("file:hidden", "true");
      }
      else
      {
        pItem.ClearProperties();
      }

      pItem.SetPath(item_path);
      items.push_back(pItem);
    }
  }

  return true;
}
