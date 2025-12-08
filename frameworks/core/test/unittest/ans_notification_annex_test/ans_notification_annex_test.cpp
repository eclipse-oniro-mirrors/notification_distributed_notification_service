/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include "ans_manager_proxy.h"
#include "ans_notification.h"
#undef private
#undef protected
#include "ans_inner_errors.h"
#include "ipc_types.h"
#include "notification.h"
#include "singleton.h"
#include "notification_subscriber.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Notification;

namespace OHOS {
namespace Notification {
class AnsNotificationUnitAnnexTest : public testing::Test {
public:
    AnsNotificationUnitAnnexTest() {}

    virtual ~AnsNotificationUnitAnnexTest() {}

    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
    std::shared_ptr<AnsNotification> ans_;
    sptr<IAnsManager> ansManagerProxy_{nullptr};
};

void AnsNotificationUnitAnnexTest::SetUpTestCase() {}

void AnsNotificationUnitAnnexTest::TearDownTestCase() {}

void AnsNotificationUnitAnnexTest::SetUp()
{
    if (!ans_) {
        ans_ = DelayedSingleton<AnsNotification>::GetInstance();
    }
}

void AnsNotificationUnitAnnexTest::TearDown() {}

/*
 * @tc.name: GetNotificationSlotNumAsBundle_0200
 * @tc.desc: test GetNotificationSlotNumAsBundle return ERR_ANS_NON_SYSTEM_APP.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitAnnexTest, GetNotificationSlotNumAsBundle_0200, Function | MediumTest | Level1)
{
    bool res = ans_->GetAnsManagerProxy();
    EXPECT_EQ(res, true);
    NotificationBundleOption bundleOption;
    std::string bundleName = "this is bundleName";
    bundleOption.SetBundleName(bundleName);
    uint64_t num = 10;
    ErrCode ret1 = ans_->GetNotificationSlotNumAsBundle(bundleOption, num);
    EXPECT_EQ(ret1, ERR_ANS_NON_SYSTEM_APP);
}

/*
 * @tc.name: PublishNotification_0100
 * @tc.desc: test PublishNotification ErrCode ERR_ANS_INVALID_PARAM.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitAnnexTest, PublishNotification_0100, Function | MediumTest | Level1)
{
    std::string label = "this is label";
    NotificationRequest request;
    request.SetContent(nullptr);

    ErrCode ret1 = ans_->PublishNotification(label, request);
    EXPECT_EQ(ret1, ERR_ANS_INVALID_PARAM);
}

/*
 * @tc.name: PublishNotificationAsBundle_0100
 * @tc.desc: test PublishNotificationAsBundle ErrCode ERR_ANS_INVALID_PARAM.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitAnnexTest, PublishNotificationAsBundle_0100, Function | MediumTest | Level1)
{
    std::string representativeBundle = "this is representativeBundle";
    NotificationRequest request;
    request.SetContent(nullptr);
    ErrCode ret5 = ans_->PublishNotificationAsBundle(representativeBundle, request);
    EXPECT_EQ(ret5, ERR_ANS_INVALID_PARAM);
}

/*
 * @tc.name: PublishNotificationAsBundle_0200
 * @tc.desc: test PublishNotificationAsBundle ErrCode ERR_ANS_INVALID_PARAM.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitAnnexTest, PublishNotificationAsBundle_0200, Function | MediumTest | Level1)
{
    std::string representativeBundle = "this is representativeBundle";
    NotificationRequest request;
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);
    request.SetContent(content);
    ErrCode ret5 = ans_->PublishNotificationAsBundle(representativeBundle, request);
    EXPECT_EQ(ret5, ERR_INVALID_OPERATION);
}

/*
 * @tc.name: RemoveNotification_0100
 * @tc.desc: test RemoveNotification ErrCode ERR_ANS_NON_SYSTEM_APP.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitAnnexTest, RemoveNotification_0100, Function | MediumTest | Level1)
{
    int32_t removeReason = 10;
    NotificationBundleOption bundleOption;
    std::string bundleName = "this is bundleName";
    bundleOption.SetBundleName(bundleName);
    int32_t notificationId = 2;
    std::string label = "this is label";
    ErrCode ret3 = ans_->RemoveNotification(bundleOption, notificationId, label, removeReason);
    EXPECT_EQ(ret3, ERR_ANS_NON_SYSTEM_APP);
}

/*
 * @tc.name: RemoveAllNotifications_0200
 * @tc.desc: test RemoveAllNotifications ErrCode ERR_ANS_NON_SYSTEM_APP.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitAnnexTest, RemoveAllNotifications_0200, Function | MediumTest | Level1)
{
    NotificationBundleOption bundleOption;
    std::string bundleName = "this is bundleName";
    bundleOption.SetBundleName(bundleName);
    ErrCode ret3 = ans_->RemoveAllNotifications(bundleOption);
    EXPECT_EQ(ret3, ERR_ANS_NON_SYSTEM_APP);
}

/*
 * @tc.name: RemoveNotificationsByBundle_0200
 * @tc.desc: test RemoveNotificationsByBundle ErrCode ERR_ANS_NON_SYSTEM_APP.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitAnnexTest, RemoveNotificationsByBundle_0200, Function | MediumTest | Level1)
{
    NotificationBundleOption bundleOption;
    std::string bundleName = "this is bundleName";
    bundleOption.SetBundleName(bundleName);
    ErrCode ret3 = ans_->RemoveNotificationsByBundle(bundleOption);
    EXPECT_EQ(ret3, ERR_ANS_NON_SYSTEM_APP);
}

/*
 * @tc.name: GetNotificationSlotsForBundle_0200
 * @tc.desc: test GetNotificationSlotsForBundle ErrCode ERR_ANS_NON_SYSTEM_APP.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitAnnexTest, GetNotificationSlotsForBundle_0200, Function | MediumTest | Level1)
{
    NotificationBundleOption bundleOption;
    std::string bundleName = "this is bundleName";
    bundleOption.SetBundleName(bundleName);
    std::vector<sptr<NotificationSlot>> slots;
    ErrCode ret3 = ans_->GetNotificationSlotsForBundle(bundleOption, slots);
    EXPECT_EQ(ret3, ERR_ANS_NON_SYSTEM_APP);
}

/*
 * @tc.name: UpdateNotificationSlots_0200
 * @tc.desc: test UpdateNotificationSlots ErrCode ERR_ANS_PERMISSION_DENIED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitAnnexTest, UpdateNotificationSlots_0200, Function | MediumTest | Level1)
{
    NotificationBundleOption bundleOption;
    std::string bundleName = "this is bundleName";
    bundleOption.SetBundleName(bundleName);
    std::vector<sptr<NotificationSlot>> slots;
    ErrCode ret3 = ans_->UpdateNotificationSlots(bundleOption, slots);
    EXPECT_EQ(ret3, ERR_ANS_INVALID_PARAM);
}

/*
 * @tc.name: RemoveGroupByBundle_0100
 * @tc.desc: test RemoveGroupByBundle ErrCode ERR_ANS_INVALID_PARAM.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitAnnexTest, RemoveGroupByBundle_0100, Function | MediumTest | Level1)
{
    std::string groupName = "";
    NotificationBundleOption bundleOption;
    std::string bundleName = "this is bundleName";
    bundleOption.SetBundleName(bundleName);
    ErrCode ret2 = ans_->RemoveGroupByBundle(bundleOption, groupName);
    EXPECT_EQ(ret2, ERR_ANS_INVALID_PARAM);
}

/*
 * @tc.name: PublishContinuousTaskNotification_0100
 * @tc.desc: test PublishContinuousTaskNotification ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitAnnexTest, PublishContinuousTaskNotification_0100, Function | MediumTest | Level1)
{
    NotificationRequest request;
    request.SetContent(nullptr);
    ErrCode ret1 = ans_->PublishContinuousTaskNotification(request);
    EXPECT_EQ(ret1, ERR_ANS_INVALID_PARAM);
}

/*
 * @tc.name: PublishContinuousTaskNotification_0200
 * @tc.desc: test PublishContinuousTaskNotification ErrCode ERR_ANS_SERVICE_NOT_CONNECTED.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitAnnexTest, PublishContinuousTaskNotification_0200, Function | MediumTest | Level1)
{
    NotificationRequest request;
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);
    request.SetContent(content);
    ErrCode ret1 = ans_->PublishContinuousTaskNotification(request);
    EXPECT_EQ(ret1, ERR_ANS_NOT_SYSTEM_SERVICE);
}

/*
 * @tc.name: CheckImageSizeForContent_0100
 * @tc.desc: test CheckImageSizeForContent.
 * @tc.type: FUNC
 * @tc.require: #I62SME
 */
HWTEST_F(AnsNotificationUnitAnnexTest, CheckImageSizeForContent_0100, Function | MediumTest | Level1)
{
    NotificationRequest request;
    request.SetContent(nullptr);

    ErrCode ret = request.CheckImageSizeForContent();
    EXPECT_EQ(ret, ERR_OK);
}
}  // namespace Notification
}  // namespace OHOS
