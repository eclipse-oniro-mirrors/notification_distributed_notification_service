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
#include <string>

#define private public
#define protected public
#include "notification_classification_mgr.h"
#undef protected
#undef private

#include "notification_classification.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationClassificationMgrTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp()
    {
        // Clear singleton state before each test to avoid inter-test interference
        NotificationClassificationMgr::GetInstance().Clear();
    };
    void TearDown()
    {
        // Clear singleton state after each test to avoid inter-test interference
        NotificationClassificationMgr::GetInstance().Clear();
    };
};

/**
 * @tc.name: AddOrUpdate_NewKey_00001
 * @tc.desc: Test AddOrUpdate with a new key adds entry to the map
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationClassificationMgrTest, AddOrUpdate_NewKey_00001, Function | SmallTest | Level1)
{
    auto& mgr = NotificationClassificationMgr::GetInstance();
    std::string key = "test_key_new";
    sptr<NotificationClassification> classification = new NotificationClassification("deal", "logistics");

    mgr.AddOrUpdate(key, classification);

    EXPECT_TRUE(mgr.Exists(key));
    EXPECT_EQ(mgr.Size(), 1);
    auto result = mgr.Get(key);
    EXPECT_NE(result, nullptr);
    EXPECT_EQ(result->GetClassification(), "deal");
    EXPECT_EQ(result->GetSubClassification(), "logistics");
}

/**
 * @tc.name: AddOrUpdate_UpdateExistingKey_00001
 * @tc.desc: Test AddOrUpdate with an existing key updates the entry
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationClassificationMgrTest, AddOrUpdate_UpdateExistingKey_00001, Function | SmallTest | Level1)
{
    auto& mgr = NotificationClassificationMgr::GetInstance();
    std::string key = "test_key_update";

    sptr<NotificationClassification> classification1 = new NotificationClassification("deal", "sub1");
    mgr.AddOrUpdate(key, classification1);
    EXPECT_EQ(mgr.Size(), 1);

    sptr<NotificationClassification> classification2 = new NotificationClassification("logistics", "sub2");
    mgr.AddOrUpdate(key, classification2);

    EXPECT_EQ(mgr.Size(), 1);
    auto result = mgr.Get(key);
    EXPECT_NE(result, nullptr);
    EXPECT_EQ(result->GetClassification(), "logistics");
    EXPECT_EQ(result->GetSubClassification(), "sub2");
}

/**
 * @tc.name: Remove_ExistingKey_00001
 * @tc.desc: Test Remove with an existing key returns true and removes the entry
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationClassificationMgrTest, Remove_ExistingKey_00001, Function | SmallTest | Level1)
{
    auto& mgr = NotificationClassificationMgr::GetInstance();
    std::string key = "test_key_remove";

    sptr<NotificationClassification> classification = new NotificationClassification("deal", "logistics");
    mgr.AddOrUpdate(key, classification);
    EXPECT_TRUE(mgr.Exists(key));
    EXPECT_EQ(mgr.Size(), 1);

    bool result = mgr.Remove(key);
    EXPECT_TRUE(result);
    EXPECT_FALSE(mgr.Exists(key));
    EXPECT_EQ(mgr.Size(), 0);
    EXPECT_EQ(mgr.Get(key), nullptr);
}

/**
 * @tc.name: Remove_NonExistingKey_00001
 * @tc.desc: Test Remove with a non-existing key returns false
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationClassificationMgrTest, Remove_NonExistingKey_00001, Function | SmallTest | Level1)
{
    auto& mgr = NotificationClassificationMgr::GetInstance();
    std::string key = "non_existing_key";

    bool result = mgr.Remove(key);
    EXPECT_FALSE(result);
    EXPECT_EQ(mgr.Size(), 0);
}

/**
 * @tc.name: Get_ExistingKey_00001
 * @tc.desc: Test Get with an existing key returns the stored classification
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationClassificationMgrTest, Get_ExistingKey_00001, Function | SmallTest | Level1)
{
    auto& mgr = NotificationClassificationMgr::GetInstance();
    std::string key = "test_key_get";

    sptr<NotificationClassification> classification = new NotificationClassification("other", "sub");
    mgr.AddOrUpdate(key, classification);

    auto result = mgr.Get(key);
    EXPECT_NE(result, nullptr);
    EXPECT_EQ(result->GetClassification(), "other");
    EXPECT_EQ(result->GetSubClassification(), "sub");
}

/**
 * @tc.name: Get_NonExistingKey_00001
 * @tc.desc: Test Get with a non-existing key returns nullptr
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationClassificationMgrTest, Get_NonExistingKey_00001, Function | SmallTest | Level1)
{
    auto& mgr = NotificationClassificationMgr::GetInstance();
    std::string key = "non_existing_key_get";

    auto result = mgr.Get(key);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: Exists_00001
 * @tc.desc: Test Exists returns true for existing key and false for non-existing key
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationClassificationMgrTest, Exists_00001, Function | SmallTest | Level1)
{
    auto& mgr = NotificationClassificationMgr::GetInstance();
    std::string existingKey = "test_key_exists";
    std::string nonExistingKey = "test_key_not_exists";

    sptr<NotificationClassification> classification = new NotificationClassification("deal", "sub");
    mgr.AddOrUpdate(existingKey, classification);

    EXPECT_TRUE(mgr.Exists(existingKey));
    EXPECT_FALSE(mgr.Exists(nonExistingKey));
}

/**
 * @tc.name: Size_00001
 * @tc.desc: Test Size returns correct count after add, update, and remove operations
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationClassificationMgrTest, Size_00001, Function | SmallTest | Level1)
{
    auto& mgr = NotificationClassificationMgr::GetInstance();

    EXPECT_EQ(mgr.Size(), 0);

    sptr<NotificationClassification> classification1 = new NotificationClassification("deal", "sub1");
    mgr.AddOrUpdate("key1", classification1);
    EXPECT_EQ(mgr.Size(), 1);

    sptr<NotificationClassification> classification2 = new NotificationClassification("logistics", "sub2");
    mgr.AddOrUpdate("key2", classification2);
    EXPECT_EQ(mgr.Size(), 2);

    // Update existing key should not increase size
    sptr<NotificationClassification> classification3 = new NotificationClassification("other", "sub3");
    mgr.AddOrUpdate("key1", classification3);
    EXPECT_EQ(mgr.Size(), 2);

    mgr.Remove("key1");
    EXPECT_EQ(mgr.Size(), 1);

    mgr.Remove("key2");
    EXPECT_EQ(mgr.Size(), 0);
}

/**
 * @tc.name: Clear_00001
 * @tc.desc: Test Clear removes all entries from the map
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationClassificationMgrTest, Clear_00001, Function | SmallTest | Level1)
{
    auto& mgr = NotificationClassificationMgr::GetInstance();

    sptr<NotificationClassification> classification1 = new NotificationClassification("deal", "sub1");
    sptr<NotificationClassification> classification2 = new NotificationClassification("logistics", "sub2");
    mgr.AddOrUpdate("key1", classification1);
    mgr.AddOrUpdate("key2", classification2);
    EXPECT_EQ(mgr.Size(), 2);

    mgr.Clear();

    EXPECT_EQ(mgr.Size(), 0);
    EXPECT_FALSE(mgr.Exists("key1"));
    EXPECT_FALSE(mgr.Exists("key2"));
    EXPECT_EQ(mgr.Get("key1"), nullptr);
    EXPECT_EQ(mgr.Get("key2"), nullptr);
}

/**
 * @tc.name: GetInstance_Singleton_00001
 * @tc.desc: Test GetInstance returns the same singleton instance
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationClassificationMgrTest, GetInstance_Singleton_00001, Function | SmallTest | Level1)
{
    auto& instance1 = NotificationClassificationMgr::GetInstance();
    auto& instance2 = NotificationClassificationMgr::GetInstance();

    EXPECT_EQ(&instance1, &instance2);
}

/**
 * @tc.name: AddOrUpdate_NullptrClassification_00001
 * @tc.desc: Test AddOrUpdate with nullptr classification still stores the entry
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationClassificationMgrTest, AddOrUpdate_NullptrClassification_00001, Function | SmallTest | Level1)
{
    auto& mgr = NotificationClassificationMgr::GetInstance();
    std::string key = "test_key_nullptr";

    mgr.AddOrUpdate(key, nullptr);

    EXPECT_TRUE(mgr.Exists(key));
    EXPECT_EQ(mgr.Size(), 1);
    auto result = mgr.Get(key);
    EXPECT_EQ(result, nullptr);
}
}
}