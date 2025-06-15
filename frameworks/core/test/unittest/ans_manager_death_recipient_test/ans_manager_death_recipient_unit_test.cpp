/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
#include <functional>
#include "gtest/gtest.h"
#define private public
#include "ans_inner_errors.h"
#include "ans_manager_death_recipient.h"
#include "iservice_registry.h"
#include "notification_helper.h"
#undef private
#include "mock_service_registry.h"
 
using namespace testing::ext;
 
extern void MockGetSystemAbilityManager(bool mockRet);
 
namespace OHOS {
namespace Notification {
class AnsManagerDeathRecipientTest : public ::testing::Test {
protected:
    void SetUp();
    void TearDown() override {}
    sptr<ISystemAbilityManager> systemAbilityManager_ = nullptr;
    sptr<MockSystemAbilityManager> mockSAMgr_ = nullptr;
};
 
void AnsManagerDeathRecipientTest::SetUp()
{
    std::cout << "AnsManagerDeathRecipientTest SetUp" << std::endl;
    mockSAMgr_ = new (std::nothrow) MockSystemAbilityManager();
    systemAbilityManager_ = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    SystemAbilityManagerClient::GetInstance().systemAbilityManager_ = mockSAMgr_;
}
 
/**
 * @tc.name      : SubscribeSAManagerTest_0100
 * @tc.desc      : Test Marshalling when SubscribeSystemAbility fail
 */
HWTEST_F(AnsManagerDeathRecipientTest, SubscribeSAManagerTest_0100, Function | MediumTest | Level1)
{
    auto ansManagerDeathRecipient = OHOS::DelayedSingleton<AnsManagerDeathRecipient>::GetInstance();
    ansManagerDeathRecipient->SubscribeSAManager();
    EXPECT_EQ(ansManagerDeathRecipient->statusChangeListener_, nullptr);
}
 
/**
 * @tc.name      : SubscribeSAManagerTest_0200
 * @tc.desc      : Test Marshalling with none null statusChangeListener
 */
HWTEST_F(AnsManagerDeathRecipientTest, SubscribeSAManagerTest_0200, Function | MediumTest | Level1)
{
    auto ansManagerDeathRecipient = OHOS::DelayedSingleton<AnsManagerDeathRecipient>::GetInstance();
    ansManagerDeathRecipient->statusChangeListener_ =
        new (std::nothrow) AnsManagerDeathRecipient::SystemAbilityStatusChangeListener();
    ansManagerDeathRecipient->SubscribeSAManager();
    EXPECT_NE(ansManagerDeathRecipient->statusChangeListener_, nullptr);
}
 
/**
 * @tc.name      : SubscribeSAManagerTest_0300
 * @tc.desc      : Test Marshalling with null systemAbilityManager
 */
HWTEST_F(AnsManagerDeathRecipientTest, SubscribeSAManagerTest_0300, Function | MediumTest | Level1)
{
    auto ansManagerDeathRecipient = OHOS::DelayedSingleton<AnsManagerDeathRecipient>::GetInstance();
    ansManagerDeathRecipient->SubscribeSAManager();
    EXPECT_NE(ansManagerDeathRecipient->statusChangeListener_, nullptr);
}
 
/**
 * @tc.name      : OnRemoveSystemAbility_0100
 * @tc.desc      : Test SystemAbility remove success
 */
HWTEST_F(AnsManagerDeathRecipientTest, OnRemoveSystemAbility_0100, Function | MediumTest | Level1)
{
    auto ansManagerDeathRecipient = OHOS::DelayedSingleton<AnsManagerDeathRecipient>::GetInstance();
    ansManagerDeathRecipient->SubscribeSAManager();
    ansManagerDeathRecipient->statusChangeListener_->OnAddSystemAbility(0, "");
    ansManagerDeathRecipient->statusChangeListener_->OnRemoveSystemAbility(0, "");
    EXPECT_NE(ansManagerDeathRecipient->statusChangeListener_, nullptr);
}
}  // namespace Notification
}  // namespace OHOS