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

#define private public
#define protected public
#include "subscriber_image_util.h"
#include "notification.h"
#include "notification_request.h"
#include "notification_live_view_content.h"
#include "notification_normal_content.h"
#include "picture_option.h"
#include "image_pixelmap_helper.h"
#undef private
#undef protected

#include "want_params.h"
#include "string_wrapper.h"
#include "array_wrapper.h"
#include "int_wrapper.h"
#include "long_wrapper.h"
#include "pixelmap_cache_manager.h"
#include "../mock/mock_application_context.h"
#include "../mock/mock_resource_manager.h"
#include "../mock/mock_image_native.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {

class SubscriberImageUtilTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        OHOS::Notification::Mock::MockResetImageNativeState();
        OHOS::AbilityRuntime::Mock::MockResetApplicationContextState();
        OHOS::Global::Resource::Mock::MockResetResourceManagerState();
    }
    
    static void TearDownTestCase() {}
    
    void SetUp() override
    {
        OHOS::Notification::Mock::MockResetImageNativeState();
        OHOS::AbilityRuntime::Mock::MockResetApplicationContextState();
        OHOS::Global::Resource::Mock::MockResetResourceManagerState();
        auto cacheManager = PixelMapCacheManager::GetInstance();
        cacheManager->RemoveCache("test_request");
        cacheManager->RemoveCache("test_request2");
    }
    
    void TearDown() override
    {
        OHOS::Notification::Mock::MockResetImageNativeState();
        OHOS::AbilityRuntime::Mock::MockResetApplicationContextState();
        OHOS::Global::Resource::Mock::MockResetResourceManagerState();
        auto cacheManager = PixelMapCacheManager::GetInstance();
        cacheManager->RemoveCache("test_request");
        cacheManager->RemoveCache("test_request2");
    }
};

/**
 * @tc.name: ProcessPictureOption_00001
 * @tc.desc: Test ProcessPictureOption with nullptr notification.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, ProcessPictureOption_00001, Function | SmallTest | Level1)
{
    sptr<PictureOption> pictureOption = new PictureOption({"pic1"});
    SubscriberImageUtil::ProcessPictureOption(nullptr, pictureOption);
    EXPECT_EQ(pictureOption->GetPreparseLiveViewPicList().size(), 1);
}

/**
 * @tc.name: ProcessPictureOption_00002
 * @tc.desc: Test ProcessPictureOption with nullptr pictureOption.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, ProcessPictureOption_00002, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    sptr<Notification> notification = new Notification(request);
    std::shared_ptr<Notification> sharedNotification = std::make_shared<Notification>(*notification);
    SubscriberImageUtil::ProcessPictureOption(sharedNotification, nullptr);
    EXPECT_NE(sharedNotification->GetNotificationRequestPoint(), nullptr);
}

/**
 * @tc.name: ProcessPictureOption_00003
 * @tc.desc: Test ProcessPictureOption with nullptr request.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, ProcessPictureOption_00003, Function | SmallTest | Level1)
{
    sptr<Notification> notification = new Notification();
    std::shared_ptr<Notification> sharedNotification = std::make_shared<Notification>(*notification);
    sptr<PictureOption> pictureOption = new PictureOption({"pic1"});
    SubscriberImageUtil::ProcessPictureOption(sharedNotification, pictureOption);
    EXPECT_EQ(sharedNotification->GetNotificationRequestPoint(), nullptr);
}

/**
 * @tc.name: ProcessPictureOption_00004
 * @tc.desc: Test ProcessPictureOption with non-LIVE_VIEW notification.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, ProcessPictureOption_00004, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    auto normalContent = std::make_shared<NotificationNormalContent>();
    auto content = std::make_shared<NotificationContent>(normalContent);
    request->SetContent(content);
    sptr<Notification> notification = new Notification(request);
    std::shared_ptr<Notification> sharedNotification = std::make_shared<Notification>(*notification);
    sptr<PictureOption> pictureOption = new PictureOption({"pic1"});
    SubscriberImageUtil::ProcessPictureOption(sharedNotification, pictureOption);
    EXPECT_NE(sharedNotification->GetNotificationRequestPoint(), nullptr);
    EXPECT_EQ(sharedNotification->GetNotificationRequestPoint()->GetNotificationType(),
        NotificationContent::Type::BASIC_TEXT);
}

/**
 * @tc.name: ProcessPictureOption_00005
 * @tc.desc: Test ProcessPictureOption with LIVE_VIEW but no extraInfo.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, ProcessPictureOption_00005, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    sptr<Notification> notification = new Notification(request);
    std::shared_ptr<Notification> sharedNotification = std::make_shared<Notification>(*notification);
    sptr<PictureOption> pictureOption = new PictureOption({"pic1"});
    SubscriberImageUtil::ProcessPictureOption(sharedNotification, pictureOption);
    EXPECT_EQ(liveViewContent->GetExtraInfo(), nullptr);
}

/**
 * @tc.name: ProcessPictureOption_00006
 * @tc.desc: Test ProcessPictureOption with empty picList.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, ProcessPictureOption_00006, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    auto extraInfo = std::make_shared<AAFwk::WantParams>();
    liveViewContent->SetExtraInfo(extraInfo);
    auto content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    sptr<Notification> notification = new Notification(request);
    std::shared_ptr<Notification> sharedNotification = std::make_shared<Notification>(*notification);
    sptr<PictureOption> pictureOption = new PictureOption();
    SubscriberImageUtil::ProcessPictureOption(sharedNotification, pictureOption);
    EXPECT_EQ(pictureOption->GetPreparseLiveViewPicList().size(), 0);
    EXPECT_TRUE(liveViewContent->GetPicture().empty());
}

/**
 * @tc.name: ProcessPictureOption_00007
 * @tc.desc: Test ProcessPictureOption with extraInfo but no matching picPath.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, ProcessPictureOption_00007, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    auto extraInfo = std::make_shared<AAFwk::WantParams>();
    liveViewContent->SetExtraInfo(extraInfo);
    auto content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    sptr<Notification> notification = new Notification(request);
    std::shared_ptr<Notification> sharedNotification = std::make_shared<Notification>(*notification);
    sptr<PictureOption> pictureOption = new PictureOption({"pic1"});
    SubscriberImageUtil::ProcessPictureOption(sharedNotification, pictureOption);
    EXPECT_NE(liveViewContent->GetExtraInfo(), nullptr);
    EXPECT_TRUE(liveViewContent->GetPicture().empty());
}

/**
 * @tc.name: ProcessPictureOption_00008
 * @tc.desc: Test ProcessPictureOption with valid extraInfo and picPath.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, ProcessPictureOption_00008, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    auto extraInfo = std::make_shared<AAFwk::WantParams>();
    extraInfo->SetParam("pic1", AAFwk::String::Box("test_path.png"));
    liveViewContent->SetExtraInfo(extraInfo);
    auto content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    sptr<Notification> notification = new Notification(request);
    std::shared_ptr<Notification> sharedNotification = std::make_shared<Notification>(*notification);
    sptr<PictureOption> pictureOption = new PictureOption({"pic1"});
    SubscriberImageUtil::ProcessPictureOption(sharedNotification, pictureOption);
    EXPECT_NE(liveViewContent->GetExtraInfo(), nullptr);
    EXPECT_TRUE(extraInfo->HasParam("pic1"));
    EXPECT_EQ(liveViewContent->GetPicture().size(), 1);
}

/**
 * @tc.name: ProcessPictureOption_00009
 * @tc.desc: Test ProcessPictureOption with multiple picPaths.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, ProcessPictureOption_00009, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    auto extraInfo = std::make_shared<AAFwk::WantParams>();
    extraInfo->SetParam("pic1", AAFwk::String::Box("path1.png"));
    extraInfo->SetParam("pic2", AAFwk::String::Box("path2.png"));
    liveViewContent->SetExtraInfo(extraInfo);
    auto content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    sptr<Notification> notification = new Notification(request);
    std::shared_ptr<Notification> sharedNotification = std::make_shared<Notification>(*notification);
    sptr<PictureOption> pictureOption = new PictureOption({"pic1", "pic2", "pic3"});
    SubscriberImageUtil::ProcessPictureOption(sharedNotification, pictureOption);
    EXPECT_TRUE(extraInfo->HasParam("pic1"));
    EXPECT_TRUE(extraInfo->HasParam("pic2"));
    EXPECT_FALSE(extraInfo->HasParam("pic3"));
    EXPECT_EQ(liveViewContent->GetPicture().size(), 2);
}

/**
 * @tc.name: ProcessPictureOption_00010
 * @tc.desc: Test ProcessPictureOption with Array<string> type.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, ProcessPictureOption_00010, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    auto extraInfo = std::make_shared<AAFwk::WantParams>();
    
    sptr<AAFwk::IArray> array = new AAFwk::Array(2, AAFwk::g_IID_IString);
    sptr<AAFwk::IInterface> str1 = AAFwk::String::Box("path1.png");
    sptr<AAFwk::IInterface> str2 = AAFwk::String::Box("path2.png");
    array->Set(0, str1.GetRefPtr());
    array->Set(1, str2.GetRefPtr());
    
    extraInfo->SetParam("pic1", array);
    liveViewContent->SetExtraInfo(extraInfo);
    auto content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    sptr<Notification> notification = new Notification(request);
    std::shared_ptr<Notification> sharedNotification = std::make_shared<Notification>(*notification);
    sptr<PictureOption> pictureOption = new PictureOption({"pic1"});
    
    SubscriberImageUtil::ProcessPictureOption(sharedNotification, pictureOption);
    EXPECT_TRUE(extraInfo->HasParam("pic1"));
    EXPECT_EQ(liveViewContent->GetPicture().size(), 1);
}

/**
 * @tc.name: ProcessPictureOption_00011
 * @tc.desc: Test ProcessPictureOption with empty Array<string>.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, ProcessPictureOption_00011, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    auto extraInfo = std::make_shared<AAFwk::WantParams>();
    
    sptr<AAFwk::IArray> array = new AAFwk::Array(0, AAFwk::g_IID_IString);
    extraInfo->SetParam("pic1", array);
    liveViewContent->SetExtraInfo(extraInfo);
    auto content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    sptr<Notification> notification = new Notification(request);
    std::shared_ptr<Notification> sharedNotification = std::make_shared<Notification>(*notification);
    sptr<PictureOption> pictureOption = new PictureOption({"pic1"});
    
    SubscriberImageUtil::ProcessPictureOption(sharedNotification, pictureOption);
    EXPECT_TRUE(extraInfo->HasParam("pic1"));
    EXPECT_EQ(liveViewContent->GetPicture().size(), 0);
}

/**
 * @tc.name: ProcessPictureOption_00012
 * @tc.desc: Test ProcessPictureOption with integer type (should skip).
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, ProcessPictureOption_00012, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    auto extraInfo = std::make_shared<AAFwk::WantParams>();
    
    extraInfo->SetParam("pic1", AAFwk::Integer::Box(12345));
    liveViewContent->SetExtraInfo(extraInfo);
    auto content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    sptr<Notification> notification = new Notification(request);
    std::shared_ptr<Notification> sharedNotification = std::make_shared<Notification>(*notification);
    sptr<PictureOption> pictureOption = new PictureOption({"pic1"});
    
    SubscriberImageUtil::ProcessPictureOption(sharedNotification, pictureOption);
    EXPECT_TRUE(extraInfo->HasParam("pic1"));
    EXPECT_EQ(liveViewContent->GetPicture().size(), 0);
}

/**
 * @tc.name: ProcessPictureOption_00013
 * @tc.desc: Test ProcessPictureOption with non-existent key.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, ProcessPictureOption_00013, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    auto extraInfo = std::make_shared<AAFwk::WantParams>();
    
    extraInfo->SetParam("otherKey", AAFwk::String::Box("test.png"));
    liveViewContent->SetExtraInfo(extraInfo);
    auto content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    sptr<Notification> notification = new Notification(request);
    std::shared_ptr<Notification> sharedNotification = std::make_shared<Notification>(*notification);
    sptr<PictureOption> pictureOption = new PictureOption({"pic1"});
    
    SubscriberImageUtil::ProcessPictureOption(sharedNotification, pictureOption);
    EXPECT_TRUE(extraInfo->HasParam("otherKey"));
    EXPECT_FALSE(extraInfo->HasParam("pic1"));
    EXPECT_EQ(liveViewContent->GetPicture().size(), 0);
}

/**
 * @tc.name: GetPixelMapByRes_00001
 * @tc.desc: Test GetPixelMapByRes when Init fails.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, GetPixelMapByRes_00001, Function | SmallTest | Level1)
{
    OHOS::Notification::Mock::MockOHImageSourceNativeCreateFromRawFileFail(true);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    auto pixelMap = SubscriberImageUtil::GetPixelMapByRes(request, "invalid.png");
    EXPECT_EQ(pixelMap, nullptr);
}

/**
 * @tc.name: GetPixelMapByRes_00002
 * @tc.desc: Test GetPixelMapByRes successfully.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, GetPixelMapByRes_00002, Function | SmallTest | Level1)
{
    OHOS::Notification::Mock::MockSetImageWidth(100);
    OHOS::Notification::Mock::MockSetImageHeight(100);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    auto pixelMap = SubscriberImageUtil::GetPixelMapByRes(request, "test.png");
    EXPECT_NE(pixelMap, nullptr);
}

/**
 * @tc.name: GetPixelMapByRes_00003
 * @tc.desc: Test GetPixelMapByRes with correct dimensions.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, GetPixelMapByRes_00003, Function | SmallTest | Level1)
{
    OHOS::Notification::Mock::MockSetImageWidth(200);
    OHOS::Notification::Mock::MockSetImageHeight(150);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    auto pixelMap = SubscriberImageUtil::GetPixelMapByRes(request, "test.png");
    EXPECT_NE(pixelMap, nullptr);
    EXPECT_EQ(pixelMap->GetWidth(), 200);
    EXPECT_EQ(pixelMap->GetHeight(), 150);
}

/**
 * @tc.name: ExtractFromStringArray_00001
 * @tc.desc: Test ExtractFromStringArray when array GetLength fails.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, ExtractFromStringArray_00001, Function | SmallTest | Level1)
{
    class MockArrayFailGetLength : public AAFwk::Array {
    public:
        MockArrayFailGetLength() : AAFwk::Array(2, AAFwk::g_IID_IString) {}
        ErrCode GetLength(long& size) override
        {
            return ERR_INVALID_VALUE;
        }
    };
    
    sptr<AAFwk::IArray> array = new MockArrayFailGetLength();
    sptr<AAFwk::IInterface> param = array;
    std::vector<std::string> picPaths;
    bool result = SubscriberImageUtil::ExtractFromStringArray(param, picPaths);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: ExtractFromStringArray_00002
 * @tc.desc: Test ExtractFromStringArray when array Get fails.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, ExtractFromStringArray_00002, Function | SmallTest | Level1)
{
    class MockArrayFailGet : public AAFwk::Array {
    public:
        MockArrayFailGet() : AAFwk::Array(2, AAFwk::g_IID_IString) {}
        ErrCode Get(long index, sptr<AAFwk::IInterface>& iface) override
        {
            return ERR_INVALID_VALUE;
        }
    };
    
    sptr<AAFwk::IArray> array = new MockArrayFailGet();
    sptr<AAFwk::IInterface> param = array;
    std::vector<std::string> picPaths;
    bool result = SubscriberImageUtil::ExtractFromStringArray(param, picPaths);
    EXPECT_EQ(result, true);
    EXPECT_TRUE(picPaths.empty());
}

/**
 * @tc.name: ExtractFromStringArray_00003
 * @tc.desc: Test ExtractFromStringArray when iface is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, ExtractFromStringArray_00003, Function | SmallTest | Level1)
{
    class MockArrayNullIface : public AAFwk::Array {
    public:
        MockArrayNullIface() : AAFwk::Array(2, AAFwk::g_IID_IString) {}
        ErrCode Get(long index, sptr<AAFwk::IInterface>& iface) override
        {
            iface = nullptr;
            return ERR_OK;
        }
    };
    
    sptr<AAFwk::IArray> array = new MockArrayNullIface();
    sptr<AAFwk::IInterface> param = array;
    std::vector<std::string> picPaths;
    bool result = SubscriberImageUtil::ExtractFromStringArray(param, picPaths);
    EXPECT_EQ(result, true);
    EXPECT_TRUE(picPaths.empty());
}

/**
 * @tc.name: ExtractFromStringArray_00004
 * @tc.desc: Test ExtractFromStringArray when element is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, ExtractFromStringArray_00004, Function | SmallTest | Level1)
{
    class MockArrayNullElement : public AAFwk::Array {
    public:
        MockArrayNullElement() : AAFwk::Array(1, AAFwk::g_IID_IString) {}
        ErrCode Get(long index, sptr<AAFwk::IInterface>& iface) override
        {
            iface = nullptr;
            return ERR_OK;
        }
    };
    
    sptr<AAFwk::IArray> array = new MockArrayNullElement();
    sptr<AAFwk::IInterface> param = array;
    std::vector<std::string> picPaths;
    bool result = SubscriberImageUtil::ExtractFromStringArray(param, picPaths);
    EXPECT_EQ(result, true);
    EXPECT_TRUE(picPaths.empty());
}

/**
 * @tc.name: ExtractFromStringArray_00005
 * @tc.desc: Test ExtractFromStringArray when path string is empty.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, ExtractFromStringArray_00005, Function | SmallTest | Level1)
{
    sptr<AAFwk::IArray> array = new AAFwk::Array(1, AAFwk::g_IID_IString);
    sptr<AAFwk::IInterface> emptyStr = AAFwk::String::Box("");
    array->Set(0, emptyStr.GetRefPtr());
    sptr<AAFwk::IInterface> param = array;
    std::vector<std::string> picPaths;
    bool result = SubscriberImageUtil::ExtractFromStringArray(param, picPaths);
    EXPECT_EQ(result, true);
    EXPECT_TRUE(picPaths.empty());
}

/**
 * @tc.name: ExtractFromString_00001
 * @tc.desc: Test ExtractFromString when param is not IString.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, ExtractFromString_00001, Function | SmallTest | Level1)
{
    sptr<AAFwk::IInterface> param = AAFwk::Integer::Box(123);
    std::vector<std::string> picPaths;
    bool result = SubscriberImageUtil::ExtractFromString(param, picPaths);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: ExtractFromString_00002
 * @tc.desc: Test ExtractFromString when string is empty.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, ExtractFromString_00002, Function | SmallTest | Level1)
{
    sptr<AAFwk::IInterface> param = AAFwk::String::Box("");
    std::vector<std::string> picPaths;
    bool result = SubscriberImageUtil::ExtractFromString(param, picPaths);
    EXPECT_EQ(result, true);
    EXPECT_TRUE(picPaths.empty());
}

/**
 * @tc.name: ExtractFromString_00003
 * @tc.desc: Test ExtractFromString with valid string.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, ExtractFromString_00003, Function | SmallTest | Level1)
{
    sptr<AAFwk::IInterface> param = AAFwk::String::Box("test.png");
    std::vector<std::string> picPaths;
    bool result = SubscriberImageUtil::ExtractFromString(param, picPaths);
    EXPECT_EQ(result, true);
    EXPECT_EQ(picPaths.size(), 1u);
    EXPECT_EQ(picPaths[0], "test.png");
}

/**
 * @tc.name: GetPicPathsFromParam_00001
 * @tc.desc: Test GetPicPathsFromParam when param not exist.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, GetPicPathsFromParam_00001, Function | SmallTest | Level1)
{
    auto extraInfo = std::make_shared<AAFwk::WantParams>();
    std::vector<std::string> picPaths = SubscriberImageUtil::GetPicPathsFromParam(extraInfo, "pic1");
    EXPECT_TRUE(picPaths.empty());
}

/**
 * @tc.name: GetPicPathsFromParam_00002
 * @tc.desc: Test GetPicPathsFromParam with string type param.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, GetPicPathsFromParam_00002, Function | SmallTest | Level1)
{
    auto extraInfo = std::make_shared<AAFwk::WantParams>();
    extraInfo->SetParam("pic1", AAFwk::String::Box("test.png"));
    std::vector<std::string> picPaths = SubscriberImageUtil::GetPicPathsFromParam(extraInfo, "pic1");
    EXPECT_EQ(picPaths.size(), 1u);
    EXPECT_EQ(picPaths[0], "test.png");
}

/**
 * @tc.name: GetPicPathsFromParam_00003
 * @tc.desc: Test GetPicPathsFromParam with array type param.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, GetPicPathsFromParam_00003, Function | SmallTest | Level1)
{
    auto extraInfo = std::make_shared<AAFwk::WantParams>();
    sptr<AAFwk::IArray> array = new AAFwk::Array(2, AAFwk::g_IID_IString);
    sptr<AAFwk::IInterface> str1 = AAFwk::String::Box("path1.png");
    sptr<AAFwk::IInterface> str2 = AAFwk::String::Box("path2.png");
    array->Set(0, str1.GetRefPtr());
    array->Set(1, str2.GetRefPtr());
    extraInfo->SetParam("pic1", array);
    std::vector<std::string> picPaths = SubscriberImageUtil::GetPicPathsFromParam(extraInfo, "pic1");
    EXPECT_EQ(picPaths.size(), 2u);
    EXPECT_EQ(picPaths[0], "path1.png");
    EXPECT_EQ(picPaths[1], "path2.png");
}

/**
 * @tc.name: GetPicPathsFromParam_00004
 * @tc.desc: Test GetPicPathsFromParam with invalid type param.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, GetPicPathsFromParam_00004, Function | SmallTest | Level1)
{
    auto extraInfo = std::make_shared<AAFwk::WantParams>();
    extraInfo->SetParam("pic1", AAFwk::Integer::Box(123));
    std::vector<std::string> picPaths = SubscriberImageUtil::GetPicPathsFromParam(extraInfo, "pic1");
    EXPECT_TRUE(picPaths.empty());
}

/**
 * @tc.name: GetPixelMapByRes_00005
 * @tc.desc: Test GetPixelMapByRes cache hit scenario.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, GetPixelMapByRes_00005, Function | SmallTest | Level1)
{
    OHOS::Notification::Mock::MockSetImageWidth(100);
    OHOS::Notification::Mock::MockSetImageHeight(100);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    auto extendInfo = std::make_shared<AAFwk::WantParams>();
    extendInfo->SetParam("versionCode", AAFwk::Long::Box(123456L));
    request->SetExtendInfo(extendInfo);
    
    auto pixelMap1 = SubscriberImageUtil::GetPixelMapByRes(request, "test.png");
    EXPECT_NE(pixelMap1, nullptr);
    
    auto pixelMap2 = SubscriberImageUtil::GetPixelMapByRes(request, "test.png");
    EXPECT_NE(pixelMap2, nullptr);
    EXPECT_EQ(pixelMap1, pixelMap2);
}

/**
 * @tc.name: GetPixelMapByRes_00006
 * @tc.desc: Test GetPixelMapByRes with versionCode=0 should not cache.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, GetPixelMapByRes_00006, Function | SmallTest | Level1)
{
    OHOS::Notification::Mock::MockSetImageWidth(100);
    OHOS::Notification::Mock::MockSetImageHeight(100);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    auto extendInfo = std::make_shared<AAFwk::WantParams>();
    extendInfo->SetParam("versionCode", AAFwk::Long::Box(0L));
    request->SetExtendInfo(extendInfo);
    
    auto pixelMap = SubscriberImageUtil::GetPixelMapByRes(request, "test.png");
    EXPECT_NE(pixelMap, nullptr);
    
    auto cacheManager = PixelMapCacheManager::GetInstance();
    auto cachedPixelMap = cacheManager->GetCachedPixelMap(request->GetKey(), "0_test.png");
    EXPECT_EQ(cachedPixelMap, nullptr);
}

/**
 * @tc.name: GetPixelMapByRes_00007
 * @tc.desc: Test GetPixelMapByRes with nullptr extendInfo.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, GetPixelMapByRes_00007, Function | SmallTest | Level1)
{
    OHOS::Notification::Mock::MockSetImageWidth(100);
    OHOS::Notification::Mock::MockSetImageHeight(100);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    request->SetExtendInfo(nullptr);
    
    auto pixelMap = SubscriberImageUtil::GetPixelMapByRes(request, "test.png");
    EXPECT_NE(pixelMap, nullptr);
    
    auto cacheManager = PixelMapCacheManager::GetInstance();
    auto cachedPixelMap = cacheManager->GetCachedPixelMap(request->GetKey(), "0_test.png");
    EXPECT_EQ(cachedPixelMap, nullptr);
}

/**
 * @tc.name: GetPixelMapByRes_00008
 * @tc.desc: Test GetPixelMapByRes without versionCode param in extendInfo.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, GetPixelMapByRes_00008, Function | SmallTest | Level1)
{
    OHOS::Notification::Mock::MockSetImageWidth(100);
    OHOS::Notification::Mock::MockSetImageHeight(100);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    auto extendInfo = std::make_shared<AAFwk::WantParams>();
    extendInfo->SetParam("otherParam", AAFwk::String::Box("value"));
    request->SetExtendInfo(extendInfo);
    
    auto pixelMap = SubscriberImageUtil::GetPixelMapByRes(request, "test.png");
    EXPECT_NE(pixelMap, nullptr);
    
    auto cacheManager = PixelMapCacheManager::GetInstance();
    auto cachedPixelMap = cacheManager->GetCachedPixelMap(request->GetKey(), "0_test.png");
    EXPECT_EQ(cachedPixelMap, nullptr);
}

/**
 * @tc.name: GetPixelMapByRes_00009
 * @tc.desc: Test GetPixelMapByRes with invalid versionCode type (not Long).
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, GetPixelMapByRes_00009, Function | SmallTest | Level1)
{
    OHOS::Notification::Mock::MockSetImageWidth(100);
    OHOS::Notification::Mock::MockSetImageHeight(100);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    auto extendInfo = std::make_shared<AAFwk::WantParams>();
    extendInfo->SetParam("versionCode", AAFwk::Integer::Box(123456));
    request->SetExtendInfo(extendInfo);
    
    auto pixelMap = SubscriberImageUtil::GetPixelMapByRes(request, "test.png");
    EXPECT_NE(pixelMap, nullptr);
    
    auto cacheManager = PixelMapCacheManager::GetInstance();
    auto cachedPixelMap = cacheManager->GetCachedPixelMap(request->GetKey(), "0_test.png");
    EXPECT_EQ(cachedPixelMap, nullptr);
}

/**
 * @tc.name: GetPixelMapByRes_00011
 * @tc.desc: Test GetPixelMapByRes when GetPixelMap returns nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, GetPixelMapByRes_00011, Function | SmallTest | Level1)
{
    OHOS::Notification::Mock::MockOHImageSourceNativeCreatePixelmapFail(true);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    
    auto pixelMap = SubscriberImageUtil::GetPixelMapByRes(request, "test.png");
    EXPECT_EQ(pixelMap, nullptr);
}

/**
 * @tc.name: GetPixelMapByRes_00012
 * @tc.desc: Test GetPixelMapByRes when GetPixelMap fails with error code.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, GetPixelMapByRes_00012, Function | SmallTest | Level1)
{
    OHOS::Notification::Mock::MockOHImageSourceNativeCreateFromRawFileFail(true);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    
    auto pixelMap = SubscriberImageUtil::GetPixelMapByRes(request, "test.png");
    EXPECT_EQ(pixelMap, nullptr);
}

/**
 * @tc.name: GetPixelMapByRes_00014
 * @tc.desc: Test GetPixelMapByRes with empty path.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, GetPixelMapByRes_00014, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    
    auto pixelMap = SubscriberImageUtil::GetPixelMapByRes(request, "");
    EXPECT_EQ(pixelMap, nullptr);
}

/**
 * @tc.name: ProcessPictureOption_00014
 * @tc.desc: Test ProcessPictureOption with multiple requests in sequence.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, ProcessPictureOption_00014, Function | SmallTest | Level1)
{
    OHOS::Notification::Mock::MockSetImageWidth(100);
    OHOS::Notification::Mock::MockSetImageHeight(100);
    
    sptr<NotificationRequest> request1 = new NotificationRequest();
    auto liveViewContent1 = std::make_shared<NotificationLiveViewContent>();
    auto extraInfo1 = std::make_shared<AAFwk::WantParams>();
    extraInfo1->SetParam("pic1", AAFwk::String::Box("path1.png"));
    liveViewContent1->SetExtraInfo(extraInfo1);
    auto content1 = std::make_shared<NotificationContent>(liveViewContent1);
    request1->SetContent(content1);
    sptr<Notification> notification1 = new Notification(request1);
    std::shared_ptr<Notification> sharedNotification1 = std::make_shared<Notification>(*notification1);
    sptr<PictureOption> pictureOption1 = new PictureOption({"pic1"});
    
    SubscriberImageUtil::ProcessPictureOption(sharedNotification1, pictureOption1);
    EXPECT_EQ(liveViewContent1->GetPicture().size(), 1);
    
    sptr<NotificationRequest> request2 = new NotificationRequest();
    auto liveViewContent2 = std::make_shared<NotificationLiveViewContent>();
    auto extraInfo2 = std::make_shared<AAFwk::WantParams>();
    extraInfo2->SetParam("pic2", AAFwk::String::Box("path2.png"));
    liveViewContent2->SetExtraInfo(extraInfo2);
    auto content2 = std::make_shared<NotificationContent>(liveViewContent2);
    request2->SetContent(content2);
    sptr<Notification> notification2 = new Notification(request2);
    std::shared_ptr<Notification> sharedNotification2 = std::make_shared<Notification>(*notification2);
    sptr<PictureOption> pictureOption2 = new PictureOption({"pic2"});
    
    SubscriberImageUtil::ProcessPictureOption(sharedNotification2, pictureOption2);
    EXPECT_EQ(liveViewContent2->GetPicture().size(), 1);
}

/**
 * @tc.name: ProcessPictureOption_00015
 * @tc.desc: Test ProcessPictureOption with failed image loading.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, ProcessPictureOption_00015, Function | SmallTest | Level1)
{
    OHOS::Notification::Mock::MockOHImageSourceNativeCreateFromRawFileFail(true);
    
    sptr<NotificationRequest> request = new NotificationRequest();
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    auto extraInfo = std::make_shared<AAFwk::WantParams>();
    extraInfo->SetParam("pic1", AAFwk::String::Box("invalid.png"));
    liveViewContent->SetExtraInfo(extraInfo);
    auto content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    sptr<Notification> notification = new Notification(request);
    std::shared_ptr<Notification> sharedNotification = std::make_shared<Notification>(*notification);
    sptr<PictureOption> pictureOption = new PictureOption({"pic1"});
    
    SubscriberImageUtil::ProcessPictureOption(sharedNotification, pictureOption);
    EXPECT_EQ(liveViewContent->GetPicture().size(), 0);
}

/**
 * @tc.name: ProcessPictureOption_00016
 * @tc.desc: Test ProcessPictureOption with mixed valid and invalid paths.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, ProcessPictureOption_00016, Function | SmallTest | Level1)
{
    OHOS::Notification::Mock::MockSetImageWidth(100);
    OHOS::Notification::Mock::MockSetImageHeight(100);
    
    sptr<NotificationRequest> request = new NotificationRequest();
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    auto extraInfo = std::make_shared<AAFwk::WantParams>();
    
    sptr<AAFwk::IArray> array = new AAFwk::Array(3, AAFwk::g_IID_IString);
    sptr<AAFwk::IInterface> str1 = AAFwk::String::Box("valid1.png");
    sptr<AAFwk::IInterface> str2 = AAFwk::String::Box("");
    sptr<AAFwk::IInterface> str3 = AAFwk::String::Box("valid2.png");
    array->Set(0, str1.GetRefPtr());
    array->Set(1, str2.GetRefPtr());
    array->Set(2, str3.GetRefPtr());
    
    extraInfo->SetParam("pics", array);
    liveViewContent->SetExtraInfo(extraInfo);
    auto content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    sptr<Notification> notification = new Notification(request);
    std::shared_ptr<Notification> sharedNotification = std::make_shared<Notification>(*notification);
    sptr<PictureOption> pictureOption = new PictureOption({"pics"});
    
    SubscriberImageUtil::ProcessPictureOption(sharedNotification, pictureOption);
    EXPECT_TRUE(extraInfo->HasParam("pics"));
    EXPECT_EQ(liveViewContent->GetPicture().size(), 1);
}

/**
 * @tc.name: ProcessPictureOption_00018
 * @tc.desc: Test ProcessPictureOption called multiple times with same notification.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, ProcessPictureOption_00018, Function | SmallTest | Level1)
{
    OHOS::Notification::Mock::MockSetImageWidth(100);
    OHOS::Notification::Mock::MockSetImageHeight(100);
    
    sptr<NotificationRequest> request = new NotificationRequest();
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    auto extraInfo = std::make_shared<AAFwk::WantParams>();
    extraInfo->SetParam("versionCode", AAFwk::Long::Box(123456L));
    extraInfo->SetParam("pic1", AAFwk::String::Box("test.png"));
    liveViewContent->SetExtraInfo(extraInfo);
    auto content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    sptr<Notification> notification = new Notification(request);
    std::shared_ptr<Notification> sharedNotification = std::make_shared<Notification>(*notification);
    sptr<PictureOption> pictureOption = new PictureOption({"pic1"});
    
    SubscriberImageUtil::ProcessPictureOption(sharedNotification, pictureOption);
    EXPECT_EQ(liveViewContent->GetPicture().size(), 1);
}

/**
 * @tc.name: ProcessPictureOption_00019
 * @tc.desc: Test ProcessPictureOption with large image dimensions (> 500).
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, ProcessPictureOption_00019, Function | SmallTest | Level1)
{
    OHOS::Notification::Mock::MockSetImageWidth(600);
    OHOS::Notification::Mock::MockSetImageHeight(600);
    
    sptr<NotificationRequest> request = new NotificationRequest();
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    auto extraInfo = std::make_shared<AAFwk::WantParams>();
    extraInfo->SetParam("pic1", AAFwk::String::Box("large.png"));
    liveViewContent->SetExtraInfo(extraInfo);
    auto content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    sptr<Notification> notification = new Notification(request);
    std::shared_ptr<Notification> sharedNotification = std::make_shared<Notification>(*notification);
    sptr<PictureOption> pictureOption = new PictureOption({"pic1"});
    
    SubscriberImageUtil::ProcessPictureOption(sharedNotification, pictureOption);
    EXPECT_EQ(liveViewContent->GetPicture().size(), 1);
}

/**
 * @tc.name: ProcessPictureOption_00020
 * @tc.desc: Test ProcessPictureOption with mixed valid and invalid keys.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, ProcessPictureOption_00020, Function | SmallTest | Level1)
{
    OHOS::Notification::Mock::MockSetImageWidth(100);
    OHOS::Notification::Mock::MockSetImageHeight(100);
    
    sptr<NotificationRequest> request = new NotificationRequest();
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    auto extraInfo = std::make_shared<AAFwk::WantParams>();
    extraInfo->SetParam("pic1", AAFwk::String::Box("path1.png"));
    extraInfo->SetParam("pic3", AAFwk::String::Box("path3.png"));
    liveViewContent->SetExtraInfo(extraInfo);
    auto content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    sptr<Notification> notification = new Notification(request);
    std::shared_ptr<Notification> sharedNotification = std::make_shared<Notification>(*notification);
    sptr<PictureOption> pictureOption = new PictureOption({"pic1", "pic2", "pic3"});
    
    SubscriberImageUtil::ProcessPictureOption(sharedNotification, pictureOption);
    EXPECT_TRUE(extraInfo->HasParam("pic1"));
    EXPECT_FALSE(extraInfo->HasParam("pic2"));
    EXPECT_TRUE(extraInfo->HasParam("pic3"));
    EXPECT_EQ(liveViewContent->GetPicture().size(), 2);
}

/**
 * @tc.name: GetPicPathsFromParam_00005
 * @tc.desc: Test GetPicPathsFromParam with special characters in path.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, GetPicPathsFromParam_00005, Function | SmallTest | Level1)
{
    auto extraInfo = std::make_shared<AAFwk::WantParams>();
    extraInfo->SetParam("pic1", AAFwk::String::Box("test image (1).png"));
    std::vector<std::string> picPaths = SubscriberImageUtil::GetPicPathsFromParam(extraInfo, "pic1");
    EXPECT_EQ(picPaths.size(), 1u);
    EXPECT_EQ(picPaths[0], "test image (1).png");
}

/**
 * @tc.name: GetPicPathsFromParam_00006
 * @tc.desc: Test GetPicPathsFromParam with long path string.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, GetPicPathsFromParam_00006, Function | SmallTest | Level1)
{
    auto extraInfo = std::make_shared<AAFwk::WantParams>();
    std::string longPath = "very/long/path/to/image/file/in/deep/directory/structure/image.png";
    extraInfo->SetParam("pic1", AAFwk::String::Box(longPath));
    std::vector<std::string> picPaths = SubscriberImageUtil::GetPicPathsFromParam(extraInfo, "pic1");
    EXPECT_EQ(picPaths.size(), 1u);
    EXPECT_EQ(picPaths[0], longPath);
}

/**
 * @tc.name: GetPicPathsFromParam_00007
 * @tc.desc: Test GetPicPathsFromParam with Array containing empty strings.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, GetPicPathsFromParam_00007, Function | SmallTest | Level1)
{
    auto extraInfo = std::make_shared<AAFwk::WantParams>();
    sptr<AAFwk::IArray> array = new AAFwk::Array(3, AAFwk::g_IID_IString);
    sptr<AAFwk::IInterface> str1 = AAFwk::String::Box("path1.png");
    sptr<AAFwk::IInterface> str2 = AAFwk::String::Box("");
    sptr<AAFwk::IInterface> str3 = AAFwk::String::Box("path2.png");
    array->Set(0, str1.GetRefPtr());
    array->Set(1, str2.GetRefPtr());
    array->Set(2, str3.GetRefPtr());
    extraInfo->SetParam("pic1", array);
    std::vector<std::string> picPaths = SubscriberImageUtil::GetPicPathsFromParam(extraInfo, "pic1");
    EXPECT_EQ(picPaths.size(), 2u);
    EXPECT_EQ(picPaths[0], "path1.png");
    EXPECT_EQ(picPaths[1], "path2.png");
}

/**
 * @tc.name: ExtractFromStringArray_00006
 * @tc.desc: Test ExtractFromStringArray with large array size.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, ExtractFromStringArray_00006, Function | SmallTest | Level1)
{
    constexpr long largeSize = 10;
    sptr<AAFwk::IArray> array = new AAFwk::Array(largeSize, AAFwk::g_IID_IString);
    for (long i = 0; i < largeSize; i++) {
        std::string path = "image" + std::to_string(i) + ".png";
        sptr<AAFwk::IInterface> str = AAFwk::String::Box(path);
        array->Set(i, str.GetRefPtr());
    }
    sptr<AAFwk::IInterface> param = array;
    std::vector<std::string> picPaths;
    bool result = SubscriberImageUtil::ExtractFromStringArray(param, picPaths);
    EXPECT_EQ(result, true);
    EXPECT_EQ(picPaths.size(), static_cast<size_t>(largeSize));
}

/**
 * @tc.name: ExtractFromString_00004
 * @tc.desc: Test ExtractFromString with long string.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, ExtractFromString_00004, Function | SmallTest | Level1)
{
    std::string longPath = "very/long/path/to/image/file/with/many/directories/final_image.png";
    sptr<AAFwk::IInterface> param = AAFwk::String::Box(longPath);
    std::vector<std::string> picPaths;
    bool result = SubscriberImageUtil::ExtractFromString(param, picPaths);
    EXPECT_EQ(result, true);
    EXPECT_EQ(picPaths.size(), 1u);
    EXPECT_EQ(picPaths[0], longPath);
}

/**
 * @tc.name: ExtractFromString_00005
 * @tc.desc: Test ExtractFromString with special characters.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(SubscriberImageUtilTest, ExtractFromString_00005, Function | SmallTest | Level1)
{
    std::string specialPath = "path/to/image (1) [test].png";
    sptr<AAFwk::IInterface> param = AAFwk::String::Box(specialPath);
    std::vector<std::string> picPaths;
    bool result = SubscriberImageUtil::ExtractFromString(param, picPaths);
    EXPECT_EQ(result, true);
    EXPECT_EQ(picPaths.size(), 1u);
    EXPECT_EQ(picPaths[0], specialPath);
}

}  // namespace Notification
}  // namespace OHOS