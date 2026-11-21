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

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <unordered_set>
#include <vector>

#include "message_parcel.h"
#include "ans_service_errors.h"

#define private public
#define protected public
#include "advanced_notification_service_ability.h"
#undef private
#undef protected
#include "boot_detector_hiview.h"
#include "notification_clean_mgr.h"
#include "notification_rdb_constant.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_store.h"
#include "rdb_store_config.h"

using namespace testing::ext;

namespace OHOS {
namespace Notification {
namespace {
const std::string ANS_RDB_FILE = "/notificationdb.db";
const std::string KEYFILE_NAME = "/keyfile";

const std::string RINGTONE_URI_A = "ans://tone-a";
const std::string RINGTONE_URI_B = "ans://tone-b";
const std::string RINGTONE_URI_C = "ans://tone-c";
const std::string RINGTONE_URI_D = "ans://tone-d";
const std::string JSON_LOCAL_A =
    R"({"ringtoneType":1,"ringtoneTitle":"ta","ringtoneFileName":"fa","ringtoneUri":"ans://tone-a"})";
const std::string JSON_LOCAL_NO_URI =
    R"({"ringtoneType":1,"ringtoneTitle":"tn","ringtoneFileName":"fn"})";
const std::string JSON_ONLINE_A =
    R"({"ringtoneType":2,"ringtoneTitle":"ta2","ringtoneFileName":"fa2","ringtoneUri":"ans://tone-a"})";
const std::string JSON_ONLINE_B =
    R"({"ringtoneType":2,"ringtoneTitle":"tb","ringtoneFileName":"fb","ringtoneUri":"ans://tone-b"})";
const std::string JSON_LOCAL_C =
    R"({"ringtoneType":1,"ringtoneTitle":"tc","ringtoneFileName":"fc","ringtoneUri":"ans://tone-c"})";
const std::string JSON_LOCAL_D =
    R"({"ringtoneType":1,"ringtoneTitle":"td","ringtoneFileName":"fd","ringtoneUri":"ans://tone-d"})";

std::string GetMirrorDbDir()
{
    return OHOS::HiviewDFX::BootDetectorReplaceDataPrefix(Infra::NtfRdbConstant::NOTIFICATION_RDB_PATH);
}

void CreateTextFile(const std::string &path)
{
    std::ofstream file(path);
    file << "ans clean test";
    file.close();
}

class TestRdbOpenCallback : public NativeRdb::RdbOpenCallback {
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

std::shared_ptr<NativeRdb::RdbStore> CreateTestRdb(const std::string &dbDir,
    const std::vector<std::string> &sqls)
{
    NativeRdb::RdbStoreConfig config(dbDir + ANS_RDB_FILE, NativeRdb::StorageMode::MODE_DISK, false,
        std::vector<uint8_t>(), "WAL", "FULL");
    config.SetSecurityLevel(NativeRdb::SecurityLevel::S1);
    TestRdbOpenCallback callback;
    int32_t errCode = NativeRdb::E_OK;
    auto store = NativeRdb::RdbHelper::GetRdbStore(config, 1, callback, errCode);
    if (store == nullptr) {
        return nullptr;
    }
    for (const auto &sql : sqls) {
        EXPECT_EQ(store->ExecuteSql(sql), NativeRdb::E_OK) << "sql: " << sql;
    }
    return store;
}

std::unordered_set<std::string> CollectUris(const std::vector<NotificationRingtoneInfo> &infos)
{
    std::unordered_set<std::string> uris;
    for (const auto &info : infos) {
        uris.insert(info.GetRingtoneUri());
    }
    return uris;
}
}  // namespace

class NotificationCleanMgrTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};

    void SetUp() override
    {
        mirrorDbDir_ = GetMirrorDbDir();
        // BootDetectorReplaceDataPrefix unconditionally rewrites the /data prefix to the
        // mirror prefix on every device, so this suite uses the rewritten directory as its
        // own scratch space (created here, removed in TearDown). Do NOT run this suite on a
        // cleanup-boot device, where that directory holds the live mirror data.
        if (mirrorDbDir_.empty()) {
            GTEST_SKIP() << "mirror db dir is empty, skip";
        }
        std::error_code ec;
        std::filesystem::create_directories(mirrorDbDir_, ec);
        ASSERT_FALSE(ec) << "create mirror dir failed: " << mirrorDbDir_;
    }

    void TearDown() override
    {
        if (mirrorDbDir_.empty()) {
            return;
        }
        std::error_code ec;
        std::filesystem::remove_all(mirrorDbDir_, ec);
        const std::filesystem::path mountPoint =
            std::filesystem::path(OHOS::HiviewDFX::BootDetectorReplaceDataPrefix("/data")).parent_path();
        std::filesystem::path parent = std::filesystem::path(mirrorDbDir_).parent_path();
        while (parent != mountPoint && parent != parent.root_path() &&
            std::filesystem::remove(parent, ec)) {
            parent = parent.parent_path();
        }
    }

protected:
    std::string mirrorDbDir_;
};

/**
 * @tc.number    : NotificationCleanMgrTest_00300
 * @tc.name      : OnExtension_00300
 * @tc.desc      : OnExtension keeps returning ERR_OK for extensions it does not handle
 */
HWTEST_F(NotificationCleanMgrTest, NotificationCleanMgrTest_00300, Function | SmallTest | Level1)
{
    AdvancedNotificationServiceAbility ability(ADVANCED_NOTIFICATION_SERVICE_ABILITY_ID, true);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(ability.OnExtension("unknown_extension", data, reply), ERR_ANS_INNER_OK);
}

/**
 * @tc.number    : NotificationCleanMgrTest_00400
 * @tc.name      : OnClean_00400
 * @tc.desc      : OnClean deletes the rdb files (db/wal/shm/journal) and the keyfile, and keeps the
 *                 notification_service directory itself
 */
HWTEST_F(NotificationCleanMgrTest, NotificationCleanMgrTest_00400, Function | SmallTest | Level1)
{
    CreateTextFile(mirrorDbDir_ + ANS_RDB_FILE);
    CreateTextFile(mirrorDbDir_ + ANS_RDB_FILE + "-wal");
    CreateTextFile(mirrorDbDir_ + ANS_RDB_FILE + "-shm");
    CreateTextFile(mirrorDbDir_ + ANS_RDB_FILE + "-journal");
    CreateTextFile(mirrorDbDir_ + KEYFILE_NAME);

    auto cleanMgr = DelayedSingleton<NotificationCleanMgr>::GetInstance();
    ASSERT_NE(cleanMgr, nullptr);
    EXPECT_EQ(cleanMgr->OnClean(), ERR_ANS_INNER_OK);

    EXPECT_FALSE(std::filesystem::exists(mirrorDbDir_ + ANS_RDB_FILE));
    EXPECT_FALSE(std::filesystem::exists(mirrorDbDir_ + ANS_RDB_FILE + "-wal"));
    EXPECT_FALSE(std::filesystem::exists(mirrorDbDir_ + ANS_RDB_FILE + "-shm"));
    EXPECT_FALSE(std::filesystem::exists(mirrorDbDir_ + ANS_RDB_FILE + "-journal"));
    EXPECT_FALSE(std::filesystem::exists(mirrorDbDir_ + KEYFILE_NAME));
    EXPECT_TRUE(std::filesystem::exists(mirrorDbDir_)) << "the mirror directory itself must be kept";
}

/**
 * @tc.number    : NotificationCleanMgrTest_00500
 * @tc.name      : OnClean_00500
 * @tc.desc      : OnClean on an empty mirror directory is idempotent and returns ERR_ANS_INNER_OK
 */
HWTEST_F(NotificationCleanMgrTest, NotificationCleanMgrTest_00500, Function | SmallTest | Level1)
{
    auto cleanMgr = DelayedSingleton<NotificationCleanMgr>::GetInstance();
    ASSERT_NE(cleanMgr, nullptr);
    EXPECT_EQ(cleanMgr->OnClean(), ERR_ANS_INNER_OK);
    EXPECT_EQ(cleanMgr->OnClean(), ERR_ANS_INNER_OK);
}

// Note: no end-to-end "real mirror rdb + OnClean" integration case here on purpose: the
// mirror open keeps SecurityLevel(S1) (aligned with the BMS mirror open, rdb_data_manager.cpp),
// which requires the filesystem behind the mirror path to support the user.security xattr. CI
// devices expose /mnt as tmpfs where that xattr is unavailable, so such a case could never
// pass there; ringtone collection against a real rdb is covered by CollectRingtoneInfos_00700
// in the temp directory, and the OnClean deletion orchestration by 00400/00500/00900.

class NotificationCollectRingtoneTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};

    void SetUp() override
    {
        // CollectRingtoneInfos only takes a directory argument, so the cases run in the
        // gtest temp directory and execute on every device, independent of the mirror-based
        // OnClean cases that run against the rewritten /mnt/data_mirror directory.
        std::string base = testing::TempDir();
        std::error_code ec;
        if (base.empty() || !std::filesystem::exists(base, ec)) {
            GTEST_SKIP() << "no temp directory available";
        }
        collectDir_ = base + "ans_collect_test";
        std::filesystem::remove_all(collectDir_, ec);
        std::filesystem::create_directories(collectDir_, ec);
        ASSERT_FALSE(ec) << "create collect test dir failed: " << collectDir_;
    }

    void TearDown() override
    {
        std::error_code ec;
        std::filesystem::remove_all(collectDir_, ec);
    }

protected:
    std::string collectDir_;
};

/**
 * @tc.number    : NotificationCleanMgrTest_00700
 * @tc.name      : CollectRingtoneInfos_00700
 * @tc.desc      : CollectRingtoneInfos reads per-bundle and clone ringtone rows from all user tables,
 *                 dedups by uri, skips rows without a parseable uri, and never reads from a table whose
 *                 name does not match notification_table or notification_table_<digits>.
 *                 Runs in a gtest temp directory so it executes on every CI device regardless of
 *                 the data mirror mapping.
 */
HWTEST_F(NotificationCollectRingtoneTest, NotificationCleanMgrTest_00700, Function | SmallTest | Level1)
{
    ASSERT_NE(CreateTestRdb(collectDir_, {
        "CREATE TABLE IF NOT EXISTS notification_table (KEY TEXT, VALUE TEXT)",
        "CREATE TABLE IF NOT EXISTS notification_table_100 (KEY TEXT, VALUE TEXT)",
        "CREATE TABLE IF NOT EXISTS notification_table_1x (KEY TEXT, VALUE TEXT)",
        "CREATE TABLE IF NOT EXISTS notification_statistics (KEY TEXT, VALUE TEXT)",
        "INSERT INTO notification_table (KEY, VALUE) VALUES "
        "('ans_bundle_com.test_bundleRingtoneNotification', '" + JSON_LOCAL_A + "')",
        "INSERT INTO notification_table (KEY, VALUE) VALUES "
        "('ans_bundle_com.test_bundleName', 'com.test')",
        "INSERT INTO notification_table (KEY, VALUE) VALUES "
        "('clone_ringtone_100_pkg', '" + JSON_ONLINE_A + "')",
        "INSERT INTO notification_table (KEY, VALUE) VALUES "
        "('clone_ringtone_101_pkg', '" + JSON_ONLINE_B + "')",
        "INSERT INTO notification_table (KEY, VALUE) VALUES "
        "('ans_bundle_com.empty_bundleRingtoneNotification', '" + JSON_LOCAL_NO_URI + "')",
        "INSERT INTO notification_table (KEY, VALUE) VALUES "
        "('ans_bundle_com.garbage_bundleRingtoneNotification', 'not a json')",
        "INSERT INTO notification_table_100 (KEY, VALUE) VALUES "
        "('ans_bundle_com.other_bundleRingtoneNotification', '" + JSON_LOCAL_C + "')",
        "INSERT INTO notification_table_1x (KEY, VALUE) VALUES "
        "('ans_bundle_com.evil_bundleRingtoneNotification', '" + JSON_LOCAL_D + "')",
        "INSERT INTO notification_statistics (KEY, VALUE) VALUES "
        "('ans_bundle_com.stat_bundleRingtoneNotification', '" + JSON_LOCAL_D + "')",
    }), nullptr);

    std::vector<NotificationRingtoneInfo> infos;
    EXPECT_EQ(NotificationCleanMgr::CollectRingtoneInfos(collectDir_, infos), ERR_ANS_INNER_OK);

    auto uris = CollectUris(infos);
    EXPECT_EQ(infos.size(), 3u);
    EXPECT_NE(uris.find(RINGTONE_URI_A), uris.end());
    EXPECT_NE(uris.find(RINGTONE_URI_B), uris.end());
    EXPECT_NE(uris.find(RINGTONE_URI_C), uris.end());
    EXPECT_EQ(uris.find(RINGTONE_URI_D), uris.end()) << "invalid table names must not be read";
}

/**
 * @tc.number    : NotificationCleanMgrTest_00800
 * @tc.name      : CollectRingtoneInfos_00800
 * @tc.desc      : CollectRingtoneInfos returns ERR_ANS_INNER_OK with an empty result when the mirror
 *                 rdb does not exist yet (nothing recorded, cleanup still proceeds)
 */
HWTEST_F(NotificationCollectRingtoneTest, NotificationCleanMgrTest_00800, Function | SmallTest | Level1)
{
    std::vector<NotificationRingtoneInfo> infos;
    EXPECT_EQ(NotificationCleanMgr::CollectRingtoneInfos(collectDir_, infos), ERR_ANS_INNER_OK);
    EXPECT_TRUE(infos.empty());
}

/**
 * @tc.number    : NotificationCleanMgrTest_00900
 * @tc.name      : OnClean_00900
 * @tc.desc      : OnClean notifies the liveview extension at the start and still completes the
 *                 cleanup whether the extension entry is loaded or not (an absent symbol is
 *                 skipped with a warning, a present entry returns ERR_OK per contract)
 */
HWTEST_F(NotificationCleanMgrTest, NotificationCleanMgrTest_00900, Function | SmallTest | Level1)
{
    CreateTextFile(mirrorDbDir_ + ANS_RDB_FILE);
    CreateTextFile(mirrorDbDir_ + KEYFILE_NAME);

    auto cleanMgr = DelayedSingleton<NotificationCleanMgr>::GetInstance();
    ASSERT_NE(cleanMgr, nullptr);
    EXPECT_EQ(cleanMgr->OnClean(), ERR_ANS_INNER_OK);

    EXPECT_FALSE(std::filesystem::exists(mirrorDbDir_ + ANS_RDB_FILE));
    EXPECT_FALSE(std::filesystem::exists(mirrorDbDir_ + KEYFILE_NAME));
}
}  // namespace Notification
}  // namespace OHOS
