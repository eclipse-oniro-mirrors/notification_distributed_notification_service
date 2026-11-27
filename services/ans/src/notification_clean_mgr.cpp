/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "notification_clean_mgr.h"

#include <filesystem>
#include <set>
#include <system_error>
#include <vector>

#include "all_scenarios_extension_wrapper.h"
#include "ans_log_wrapper.h"
#include "ans_service_errors.h"
#include "boot_detector_hiview.h"
#include "notification_rdb_constant.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_store.h"
#include "rdb_store_config.h"
#include "system_sound_helper.h"

namespace OHOS {
namespace Notification {
namespace {
const std::string ANS_RDB_FILE = Infra::NtfRdbConstant::NOTIFICATION_RDB_NAME;
const std::string KEYFILE_DIR = "/keyfile";
const std::string RINGTONE_KEY_SUFFIX = "bundleRingtoneNotification";
const std::string CLONE_RINGTONE_KEY_PREFIX = "clone_ringtone_";

bool IsValidTableName(const std::string &name)
{
    if (name == Infra::NtfRdbConstant::NOTIFICATION_RDB_TABLE_NAME) {
        return true;
    }
    const std::string prefix = std::string(Infra::NtfRdbConstant::NOTIFICATION_RDB_TABLE_NAME) + "_";
    if (name.size() <= prefix.size() || name.compare(0, prefix.size(), prefix) != 0) {
        return false;
    }
    return name.find_first_not_of("0123456789", prefix.size()) == std::string::npos;
}

class MirrorRdbOpenCallback : public NativeRdb::RdbOpenCallback {
public:
    int OnCreate(NativeRdb::RdbStore &rdbStore) override
    {
        return NativeRdb::E_OK;
    }

    int OnUpgrade(NativeRdb::RdbStore &rdbStore, int currentVersion, int targetVersion) override
    {
        return NativeRdb::E_OK;
    }
};

void CollectRingtoneInfosFromTable(const std::shared_ptr<NativeRdb::RdbStore> &store,
    const std::string &tableName, std::set<std::string> &collectedUris,
    std::vector<NotificationRingtoneInfo> &ringtoneInfos)
{
    const std::string sql = "SELECT VALUE FROM " + tableName + " WHERE KEY LIKE '%" + RINGTONE_KEY_SUFFIX +
        "' OR KEY LIKE '" + CLONE_RINGTONE_KEY_PREFIX + "%'";
    auto resultSet = store->QuerySql(sql);
    if (resultSet == nullptr) {
        ANS_LOGE("BOPD clean: query ringtone from %{public}s failed", tableName.c_str());
        return;
    }
    std::string value;
    int32_t ret = resultSet->GoToFirstRow();
    while (ret == NativeRdb::E_OK) {
        if (resultSet->GetString(0, value) == NativeRdb::E_OK) {
            NotificationRingtoneInfo ringtoneInfo;
            ringtoneInfo.FromJson(value);
            const std::string &uri = ringtoneInfo.GetRingtoneUri();
            if (!uri.empty() && collectedUris.insert(uri).second) {
                ringtoneInfos.push_back(ringtoneInfo);
            }
        }
        ret = resultSet->GoToNextRow();
    }
    resultSet->Close();
}
}  // namespace

NotificationCleanMgr::NotificationCleanMgr() {}

NotificationCleanMgr::~NotificationCleanMgr() {}

int32_t NotificationCleanMgr::OnClean()
{
    ANS_LOGI("NotificationCleanMgr OnClean start");
    std::string mirrorDbDir = GetMirrorDbDir();
    if (mirrorDbDir.empty()) {
        ANS_LOGE("BOPD clean: get mirror db dir failed");
        return ERR_ANS_INNER_INVALID_OPERATION;
    }
    NotifyCleanupStart();
    CleanCustomizedTones(mirrorDbDir);
    int32_t ret = CleanRdbFiles(mirrorDbDir);
    if (ret != ERR_ANS_INNER_OK) {
        ANS_LOGE("BOPD clean: clean rdb files failed, err is %{public}d.", ret);
        return ret;
    }
    ret = CleanKeyFileDir(mirrorDbDir);
    if (ret != ERR_ANS_INNER_OK) {
        ANS_LOGE("BOPD clean: clean keyfile dir failed, err is %{public}d.", ret);
        return ret;
    }
    ANS_LOGI("NotificationCleanMgr OnClean end");
    return ERR_ANS_INNER_OK;
}

void NotificationCleanMgr::NotifyCleanupStart()
{
    ANS_LOGI("BOPD clean: notify cleanup start to extension");
    ErrCode ret = Infra::ALL_SCENARIOS_EXTENTION_WRAPPER.OnCleanup();
    if (ret != ERR_OK) {
        ANS_LOGW("BOPD clean: OnCleanup failed, err is %{public}d.", ret);
        return;
    }
    ANS_LOGI("BOPD clean: OnCleanup notified, extension returns ERR_OK");
}

void NotificationCleanMgr::CleanCustomizedTones(const std::string &mirrorDbDir)
{
    std::vector<NotificationRingtoneInfo> ringtoneInfos;
    int32_t ret = CollectRingtoneInfos(mirrorDbDir, ringtoneInfos);
    if (ret != ERR_ANS_INNER_OK) {
        ANS_LOGW("BOPD clean: collect ringtone infos failed, err is %{public}d.", ret);
        return;
    }
    if (ringtoneInfos.empty()) {
        ANS_LOGI("BOPD clean: no customized tone to remove");
        return;
    }
    ANS_LOGI("BOPD clean: remove %{public}zu customized tones", ringtoneInfos.size());
    SystemSoundHelper::GetInstance()->RemoveCustomizedTones(ringtoneInfos);
}

int32_t NotificationCleanMgr::CollectRingtoneInfos(const std::string &mirrorDbDir,
    std::vector<NotificationRingtoneInfo> &ringtoneInfos)
{
    std::string dbPath = mirrorDbDir + ANS_RDB_FILE;
    std::error_code existsErr;
    if (!std::filesystem::exists(dbPath, existsErr)) {
        // Also covers a stat error such as EACCES on the mirror mount: taking the soft
        // path here avoids an uncaught filesystem_error on the OnExtension IPC thread.
        ANS_LOGI("BOPD clean: mirror rdb does not exist or not accessible, path=%{public}s, err is %{public}d",
            dbPath.c_str(), existsErr.value());
        return ERR_ANS_INNER_OK;
    }
    NativeRdb::RdbStoreConfig config(dbPath, NativeRdb::StorageMode::MODE_DISK, false,
        std::vector<uint8_t>(), Infra::NtfRdbConstant::NOTIFICATION_JOURNAL_MODE,
        Infra::NtfRdbConstant::NOTIFICATION_SYNC_MODE);
    config.SetSecurityLevel(NativeRdb::SecurityLevel::S1);
    config.SetHaMode(NativeRdb::HAMode::MAIN_REPLICA);
    MirrorRdbOpenCallback callback;
    int32_t errCode = NativeRdb::E_OK;
    // GetRdbStore really opens the store; GetRdb is only a process-local cache lookup and
    // always returns nullptr for the mirror path, which nobody opened before the cleanup.
    auto store = NativeRdb::RdbHelper::GetRdbStore(config, Infra::NtfRdbConstant::NOTIFICATION_RDB_VERSION,
        callback, errCode);
    if (store == nullptr) {
        // The mirror db may be corrupt; the rdb files are deleted right after this anyway,
        // so a collection failure is tolerated and the cleanup proceeds.
        ANS_LOGW("BOPD clean: open mirror rdb failed, err is %{public}d", errCode);
        return ERR_ANS_INNER_OK;
    }
    auto tables = store->QuerySql("SELECT name FROM sqlite_master WHERE type='table'");
    if (tables == nullptr) {
        ANS_LOGE("BOPD clean: query sqlite_master failed");
        NativeRdb::RdbHelper::ClearStoreCache(config);
        return ERR_ANS_INNER_INVALID_OPERATION;
    }
    std::set<std::string> collectedUris;
    std::string tableName;
    int32_t ret = tables->GoToFirstRow();
    while (ret == NativeRdb::E_OK) {
        if (tables->GetString(0, tableName) != NativeRdb::E_OK) {
            ANS_LOGE("BOPD clean: get table name failed");
            break;
        }
        if (IsValidTableName(tableName)) {
            CollectRingtoneInfosFromTable(store, tableName, collectedUris, ringtoneInfos);
        }
        ret = tables->GoToNextRow();
    }
    tables->Close();
    NativeRdb::RdbHelper::ClearStoreCache(config);
    return ERR_ANS_INNER_OK;
}

int32_t NotificationCleanMgr::CleanRdbFiles(const std::string &mirrorDbDir)
{
    NativeRdb::RdbStoreConfig config(mirrorDbDir + ANS_RDB_FILE, NativeRdb::StorageMode::MODE_DISK, false,
        std::vector<uint8_t>(), Infra::NtfRdbConstant::NOTIFICATION_JOURNAL_MODE,
        Infra::NtfRdbConstant::NOTIFICATION_SYNC_MODE);
    config.SetSecurityLevel(NativeRdb::SecurityLevel::S1);
    config.SetHaMode(NativeRdb::HAMode::MAIN_REPLICA);
    int32_t ret = NativeRdb::RdbHelper::DeleteRdbStore(config);
    if (ret != NativeRdb::E_OK) {
        ANS_LOGE("BOPD clean: delete rdb store failed, err is %{public}d", ret);
        return ERR_ANS_INNER_INVALID_OPERATION;
    }
    ANS_LOGI("BOPD clean: notification rdb files removed on mirror path");
    return ERR_ANS_INNER_OK;
}

int32_t NotificationCleanMgr::CleanKeyFileDir(const std::string &mirrorDbDir)
{
    std::string keyFileDir = mirrorDbDir + KEYFILE_DIR;
    std::error_code ec;
    std::filesystem::remove_all(keyFileDir, ec);
    if (ec && ec != std::errc::no_such_file_or_directory) {
        ANS_LOGE("BOPD clean: remove keyfile dir failed, err is %{public}d", ec.value());
        return ERR_ANS_INNER_INVALID_OPERATION;
    }
    ANS_LOGI("BOPD clean: keyfile dir removed on mirror path");
    return ERR_ANS_INNER_OK;
}

std::string NotificationCleanMgr::GetMirrorDbDir()
{
    std::string mirrorPath =
        OHOS::HiviewDFX::BootDetectorReplaceDataPrefix(Infra::NtfRdbConstant::NOTIFICATION_RDB_PATH);
    if (mirrorPath.empty() || mirrorPath == Infra::NtfRdbConstant::NOTIFICATION_RDB_PATH) {
        ANS_LOGE("BOPD clean: BootDetectorReplaceDataPrefix returned unchanged path=%{public}s",
            Infra::NtfRdbConstant::NOTIFICATION_RDB_PATH);
        return "";
    }
    return mirrorPath;
}
}  // namespace Notification
}  // namespace OHOS
