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

#include <gtest/gtest.h>

#define private public
#define protected public
#include "ans_manager_death_recipient.h"
#include "ans_notification.h"
#undef private
#undef protected

#include "singleton.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Notification;

class AnsManagerDeathRecipientUnitTest : public testing::Test {
public:
    AnsManagerDeathRecipientUnitTest() {}

    virtual ~AnsManagerDeathRecipientUnitTest() {}

    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
};

void AnsManagerDeathRecipientUnitTest::SetUpTestCase() {}

void AnsManagerDeathRecipientUnitTest::TearDownTestCase() {}

void AnsManagerDeathRecipientUnitTest::SetUp() {}

void AnsManagerDeathRecipientUnitTest::TearDown() {}

/*
 * @tc.name: SubscribeSAManagerTest_0100
 * @tc.desc: test if AnsManagerDeathRecipient's SubscribeSAManager function executed as expected in normal case.
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsManagerDeathRecipientUnitTest, SubscribeSAManagerTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerDeathRecipientUnitTest, SubscribeSAManagerTest_0100, TestSize.Level1";
    auto ansManagerDeathRecipient = OHOS::DelayedSingleton<AnsManagerDeathRecipient>::GetInstance();
    ansManagerDeathRecipient->SubscribeSAManager();
    EXPECT_EQ(true, ansManagerDeathRecipient->GetIsSubscribeSAManager());
}

/*
 * @tc.name: OnRemoveSystemAbilityTest_0100
 * @tc.desc: test if AnsManagerDeathRecipient's OnRemoveSystemAbility function executed as expected in normal case.
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsManagerDeathRecipientUnitTest, OnRemoveSystemAbilityTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerDeathRecipientUnitTest, OnRemoveSystemAbilityTest_0100, TestSize.Level1";
    auto ansManagerDeathRecipient = OHOS::DelayedSingleton<AnsManagerDeathRecipient>::GetInstance();
    ansManagerDeathRecipient->SubscribeSAManager();
    ansManagerDeathRecipient->statusChangeListener_->OnRemoveSystemAbility(0, "");
    auto ansNotification = OHOS::DelayedSingleton<AnsNotification>::GetInstance();
    EXPECT_TRUE(ansNotification->ansManagerProxy_ == nullptr);
}

/*
 * @tc.name: OnAddSystemAbilityTest_0100
 * @tc.desc: test if AnsManagerDeathRecipient's OnAddSystemAbility function executed as expected in normal case.
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsManagerDeathRecipientUnitTest, OnAddSystemAbilityTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerDeathRecipientUnitTest, OnAddSystemAbilityTest_0100, TestSize.Level1";
    auto ansManagerDeathRecipient = OHOS::DelayedSingleton<AnsManagerDeathRecipient>::GetInstance();
    ansManagerDeathRecipient->SubscribeSAManager();
    ansManagerDeathRecipient->statusChangeListener_->OnRemoveSystemAbility(0, "");
    ansManagerDeathRecipient->statusChangeListener_->OnAddSystemAbility(0, "");
    auto ansNotification = OHOS::DelayedSingleton<AnsNotification>::GetInstance();
    EXPECT_TRUE(ansNotification->ansManagerProxy_ != nullptr);
}
