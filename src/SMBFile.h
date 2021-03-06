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

#include <kodi/addon-instance/VFS.h>
#include <kodi/Filesystem.h>
#include <kodi/General.h>

struct SMBContext
{
  uint32_t pFileHandle;
  int64_t size;
  struct smb_session* pSession;
  std::string sharename;
  std::string filename;
};

class CSMBFile : public kodi::addon::CInstanceVFS
{
public:
  CSMBFile(KODI_HANDLE instance);
  virtual ~CSMBFile();
  virtual void* Open(const VFSURL& url) override;
  virtual ssize_t Read(void* context, void* lpBuf, size_t uiBufSize) override;
  virtual int64_t Seek(void* context, int64_t iFilePosition, int iWhence) override;
  virtual int64_t GetLength(void* context) override;
  virtual int64_t GetPosition(void* context) override;
  virtual int GetChunkSize(void* context) override {return 16386;}
  virtual int IoControl(void* context, XFILE::EIoControl request, void* param) override;
  virtual int Stat(const VFSURL& url, struct __stat64* buffer) override;
  virtual bool Close(void* context) override;
  virtual bool Exists(const VFSURL& url) override;
  virtual bool GetDirectory(const VFSURL& url, std::vector<kodi::vfs::CDirEntry>& items, CVFSCallbacks callbacks) override;
};

class ATTRIBUTE_HIDDEN CMyAddon : public kodi::addon::CAddonBase
{
public:
  CMyAddon() { }
  virtual ADDON_STATUS CreateInstance(int instanceType, std::string instanceID, KODI_HANDLE instance, KODI_HANDLE& addonInstance) override
  {
    addonInstance = new CSMBFile(instance);
    return ADDON_STATUS_OK;
  }
};

ADDONCREATOR(CMyAddon);
