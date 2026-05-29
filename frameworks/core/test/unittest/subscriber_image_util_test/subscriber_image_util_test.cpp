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
    
    void SetUp()
    {
        OHOS::Notification::Mock::MockResetImageNativeState();
        OHOS::AbilityRuntime::Mock::MockResetApplicationContextState();
        OHOS::Global::Resource::Mock::MockResetResourceManagerState();
    }
    
    void TearDown()
    {
        OHOS::Notification::Mock::MockResetImageNativeState();
        OHOS::AbilityRuntime::Mock::MockResetApplicationContextState();
        OHOS::Global::Resource::Mock::MockResetResourceManagerState();
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

}  // namespace Notification
}  // namespace OHOS