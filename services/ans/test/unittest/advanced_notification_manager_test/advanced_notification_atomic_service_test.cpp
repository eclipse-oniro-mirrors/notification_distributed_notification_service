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

#include "gtest/gtest.h"
#define private public
#include "advanced_notification_service.h"
#include "notification_bundle_option.h"
#include "notification_request.h"

using namespace testing::ext;

namespace OHOS {
namespace Notification {

extern void MockIsSystemApp(bool isSystemApp);
extern void MockIsVerfyPermisson(bool isVerify);

class AdvancedNotificationAtomicServiceTest : public testing::Test {
public:
    void SetUp() override
    {
        MockIsSystemApp(true);
        MockIsVerfyPermisson(true);
    }
    void TearDown() override {}
};

static sptr<AdvancedNotificationService> GetService()
{
    return new AdvancedNotificationService();
}

/**
 * @tc.name: CheckAndPrepareNotificationInfoWithAtomicService_CheckUserIdFailed_00001
 * @tc.desc: Test CheckAndPrepareNotificationInfoWithAtomicService with CheckUserIdParams failed
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationAtomicServiceTest, CheckUserIdParamsFailed_00001, Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetCreatorUserId(0);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("testBundle", 100);
    
    auto result = service->CheckAndPrepareNotificationInfoWithAtomicService(request, bundle);
    EXPECT_NE(result.GetErrCode(), ERR_OK);
}

/**
 * @tc.name: CheckAndPrepareNotificationInfoWithAtomicService_OwnerUserIdInvalid_00001
 * @tc.desc: Test CheckAndPrepareNotificationInfoWithAtomicService with invalid OwnerUserId
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationAtomicServiceTest, OwnerUserIdInvalid_00001, Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetCreatorUserId(100);
    request->SetOwnerUserId(-1);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("testBundle", 100);
    
    auto result = service->CheckAndPrepareNotificationInfoWithAtomicService(request, bundle);
    EXPECT_NE(result.GetErrCode(), ERR_OK);
}

/**
 * @tc.name: CheckAndPrepareNotificationInfoWithAtomicService_EmptyOwnerBundleName_00001
 * @tc.desc: Test CheckAndPrepareNotificationInfoWithAtomicService with empty OwnerBundleName
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationAtomicServiceTest, EmptyOwnerBundleName_00001, Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetCreatorUserId(100);
    request->SetOwnerUserId(100);
    request->SetOwnerBundleName("");
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("testBundle", 100);
    
    auto result = service->CheckAndPrepareNotificationInfoWithAtomicService(request, bundle);
    EXPECT_NE(result.GetErrCode(), ERR_OK);
}

/**
 * @tc.name: CheckAndPrepareNotificationInfoWithAtomicService_InvalidDeliveryTime_00001
 * @tc.desc: Test CheckAndPrepareNotificationInfoWithAtomicService with invalid deliveryTime
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationAtomicServiceTest, InvalidDeliveryTime_00001, Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetCreatorUserId(100);
    request->SetOwnerUserId(100);
    request->SetOwnerBundleName("testOwner");
    request->SetDeliveryTime(0);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("testBundle", 100);
    
    auto result = service->CheckAndPrepareNotificationInfoWithAtomicService(request, bundle);
    EXPECT_EQ(result.GetErrCode(), ERR_OK);
}

/**
 * @tc.name: SetCreatorInfoWithAtomicService_NullExtendInfo_00001
 * @tc.desc: Test SetCreatorInfoWithAtomicService with null extendInfo
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationAtomicServiceTest,
    SetCreatorInfoWithAtomicService_NullExtendInfo_00001, Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> request = new NotificationRequest();
    
    auto result = service->SetCreatorInfoWithAtomicService(request);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: AtomicServicePublish_ValidRequest_00001
 * @tc.desc: Test AtomicServicePublish with valid request
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationAtomicServiceTest, AtomicServicePublish_ValidRequest_00001, Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> request = new NotificationRequest();
    
    auto result = service->AtomicServicePublish(request);
    EXPECT_NE(result.GetErrCode(), ERR_OK);
}
}  // namespace Notification
}  // namespace OHOS