/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <memory>

#include "gtest/gtest.h"

#define private public
#include "distributed_database_callback.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class DistributedDatabaseCallbackTest : public testing::Test {
public:
    void SetUp() override;
    void TearDown() override;

public:
    virtual void OnInsert(const std::string &deviceId, const std::string &key, const std::string &value);
    virtual void OnUpdate(const std::string &deviceId, const std::string &key, const std::string &value);
    virtual void OnDelete(const std::string &deviceId, const std::string &key, const std::string &value);
};

void DistributedDatabaseCallbackTest::SetUp()
{}

void DistributedDatabaseCallbackTest::TearDown()
{}

void DistributedDatabaseCallbackTest::OnInsert(
    const std::string &deviceId, const std::string &key, const std::string &value) {}

void DistributedDatabaseCallbackTest::OnUpdate(
    const std::string &deviceId, const std::string &key, const std::string &value) {}

void DistributedDatabaseCallbackTest::OnDelete(
    const std::string &deviceId, const std::string &key, const std::string &value) {}

/**
 * @tc.name      : DistributedDatabaseCallback_00100
 * @tc.number    : DistributedDatabaseCallback_00100
 * @tc.desc      : test OnChange function and callback_.OnInsert is nullptr .
 */
HWTEST_F(DistributedDatabaseCallbackTest, DistributedDatabaseCallback_00100, Function | SmallTest | Level1)
{
    DistributedDatabaseCallback::IDatabaseChange databaseCallback = {
        .OnInsert = std::bind(&DistributedDatabaseCallbackTest::OnInsert,
            this,
            std::placeholders::_1,
            std::placeholders::_2,
            std::placeholders::_3),
        .OnUpdate = std::bind(&DistributedDatabaseCallbackTest::OnUpdate,
            this,
            std::placeholders::_1,
            std::placeholders::_2,
            std::placeholders::_3),
        .OnDelete = std::bind(&DistributedDatabaseCallbackTest::OnDelete,
            this,
            std::placeholders::_1,
            std::placeholders::_2,
            std::placeholders::_3),
    };
    std::shared_ptr<DistributedDatabaseCallback> databaseCallback_ =
        std::make_shared<DistributedDatabaseCallback>(databaseCallback);
    ASSERT_NE(nullptr, databaseCallback_);
    databaseCallback_->callback_.OnInsert = nullptr;
    std::vector<DistributedKv::Entry> insertEntries;
    std::vector<DistributedKv::Entry> updateEntries;
    std::vector<DistributedKv::Entry> deleteEntries;
    DistributedKv::ChangeNotification changeNotification(
        std::move(insertEntries), std::move(updateEntries), std::move(deleteEntries), "<remoteDeviceId>", false);
    databaseCallback_->OnChange(changeNotification);
}

/**
 * @tc.name      : DistributedDatabaseCallback_00200
 * @tc.number    : DistributedDatabaseCallback_00200
 * @tc.desc      : test OnChange function and callback_.OnUpdate is nullptr .
 */
HWTEST_F(DistributedDatabaseCallbackTest, DistributedDatabaseCallback_00200, Function | SmallTest | Level1)
{
    DistributedDatabaseCallback::IDatabaseChange databaseCallback = {
        .OnInsert = std::bind(&DistributedDatabaseCallbackTest::OnInsert,
            this,
            std::placeholders::_1,
            std::placeholders::_2,
            std::placeholders::_3),
        .OnUpdate = std::bind(&DistributedDatabaseCallbackTest::OnUpdate,
            this,
            std::placeholders::_1,
            std::placeholders::_2,
            std::placeholders::_3),
        .OnDelete = std::bind(&DistributedDatabaseCallbackTest::OnDelete,
            this,
            std::placeholders::_1,
            std::placeholders::_2,
            std::placeholders::_3),
    };
    std::shared_ptr<DistributedDatabaseCallback> databaseCallback_ =
        std::make_shared<DistributedDatabaseCallback>(databaseCallback);
    ASSERT_NE(nullptr, databaseCallback_);
    databaseCallback_->callback_.OnUpdate = nullptr;
    std::vector<DistributedKv::Entry> insertEntries;
    std::vector<DistributedKv::Entry> updateEntries;
    std::vector<DistributedKv::Entry> deleteEntries;
    DistributedKv::ChangeNotification changeNotification(
        std::move(insertEntries), std::move(updateEntries), std::move(deleteEntries), "<remoteDeviceId>", false);
    databaseCallback_->OnChange(changeNotification);
}

/**
 * @tc.name      : DistributedDatabaseCallback_00300
 * @tc.number    : DistributedDatabaseCallback_00300
 * @tc.desc      : test OnChange function and callback_.OnDelete is nullptr .
 */
HWTEST_F(DistributedDatabaseCallbackTest, DistributedDatabaseCallback_00300, Function | SmallTest | Level1)
{
    DistributedDatabaseCallback::IDatabaseChange databaseCallback = {
        .OnInsert = std::bind(&DistributedDatabaseCallbackTest::OnInsert,
            this,
            std::placeholders::_1,
            std::placeholders::_2,
            std::placeholders::_3),
        .OnUpdate = std::bind(&DistributedDatabaseCallbackTest::OnUpdate,
            this,
            std::placeholders::_1,
            std::placeholders::_2,
            std::placeholders::_3),
        .OnDelete = std::bind(&DistributedDatabaseCallbackTest::OnDelete,
            this,
            std::placeholders::_1,
            std::placeholders::_2,
            std::placeholders::_3),
    };
    std::shared_ptr<DistributedDatabaseCallback> databaseCallback_ =
        std::make_shared<DistributedDatabaseCallback>(databaseCallback);
    ASSERT_NE(nullptr, databaseCallback_);
    databaseCallback_->callback_.OnDelete = nullptr;
    std::vector<DistributedKv::Entry> insertEntries;
    std::vector<DistributedKv::Entry> updateEntries;
    std::vector<DistributedKv::Entry> deleteEntries;
    DistributedKv::ChangeNotification changeNotification(
        std::move(insertEntries), std::move(updateEntries), std::move(deleteEntries), "<remoteDeviceId>", false);
    databaseCallback_->OnChange(changeNotification);
}
}  // namespace Notification
}  // namespace OHOS