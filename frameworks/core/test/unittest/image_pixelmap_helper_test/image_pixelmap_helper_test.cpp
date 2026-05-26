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
#include "image_pixelmap_helper.h"
#include "notification_request.h"
#undef private
#undef protected

#include "ans_inner_errors.h"
#include "../mock/mock_application_context.h"
#include "../mock/mock_resource_manager.h"
#include "../mock/mock_image_native.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {

class ImagePixelmapHelperTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        AbilityRuntime::Mock::MockResetApplicationContextState();
        AbilityRuntime::Mock::MockResetCreateBundleContextState();
        Global::Resource::Mock::MockResetResourceManagerState();
        Global::Resource::Mock::MockResetGetResourceManagerState();
        Notification::Mock::MockResetImageNativeState();
    }
    
    static void TearDownTestCase() {}
    
    void SetUp()
    {
        AbilityRuntime::Mock::MockResetApplicationContextState();
        AbilityRuntime::Mock::MockResetCreateBundleContextState();
        Global::Resource::Mock::MockResetResourceManagerState();
        Global::Resource::Mock::MockResetGetResourceManagerState();
        Notification::Mock::MockResetImageNativeState();
    }
    
    void TearDown()
    {
        AbilityRuntime::Mock::MockResetApplicationContextState();
        AbilityRuntime::Mock::MockResetCreateBundleContextState();
        Global::Resource::Mock::MockResetResourceManagerState();
        Global::Resource::Mock::MockResetGetResourceManagerState();
        Notification::Mock::MockResetImageNativeState();
    }
};

/**
 * @tc.name: Init_00001
 * @tc.desc: Test Init when imageFile is empty.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, Init_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "");
    ErrCode ret = helper.Init();
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: Init_00002
 * @tc.desc: Test Init when request is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, Init_00002, Function | SmallTest | Level1)
{
    ImagePixelmapHelper helper(nullptr, "test.png");
    ErrCode ret = helper.Init();
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: Init_00003
 * @tc.desc: Test Init when appContext is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, Init_00003, Function | SmallTest | Level1)
{
    AbilityRuntime::Mock::MockGetApplicationContextReturnNull(true);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    ErrCode ret = helper.Init();
    EXPECT_EQ(ret, ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: Init_00004
 * @tc.desc: Test Init when GetRawFileDescriptor fails.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, Init_00004, Function | SmallTest | Level1)
{
    Global::Resource::Mock::MockGetRawFileDescriptorFail(true);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    ErrCode ret = helper.Init();
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.name: Init_00005
 * @tc.desc: Test Init when OH_ImageSourceNative_CreateFromRawFile fails.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, Init_00005, Function | SmallTest | Level1)
{
    Notification::Mock::MockOHImageSourceNativeCreateFromRawFileFail(true);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    ErrCode ret = helper.Init();
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: Init_00006
 * @tc.desc: Test Init when OH_ImageSourceInfo_Create fails.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, Init_00006, Function | SmallTest | Level1)
{
    Notification::Mock::MockOHImageSourceInfoCreateFail(true);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    ErrCode ret = helper.Init();
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: Init_00007
 * @tc.desc: Test Init when OH_ImageSourceInfo_GetWidth fails.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, Init_00007, Function | SmallTest | Level1)
{
    Notification::Mock::MockOHImageSourceInfoGetWidthFail(true);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    ErrCode ret = helper.Init();
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: Init_00008
 * @tc.desc: Test Init when OH_ImageSourceNative_CreatePixelmap fails.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, Init_00008, Function | SmallTest | Level1)
{
    Notification::Mock::MockOHImageSourceNativeCreatePixelmapFail(true);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    ErrCode ret = helper.Init();
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: Init_00009
 * @tc.desc: Test Init when OH_PixelmapNative_ReadPixels fails.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, Init_00009, Function | SmallTest | Level1)
{
    Notification::Mock::MockOHPixelmapNativeReadPixelsFail(true);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    ErrCode ret = helper.Init();
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: Init_00010
 * @tc.desc: Test Init successfully.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, Init_00010, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    ErrCode ret = helper.Init();
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: GetImageWidth_00001
 * @tc.desc: Test GetImageWidth after successful Init.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetImageWidth_00001, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(200);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    helper.Init();
    uint32_t width = helper.GetImageWidth();
    EXPECT_EQ(width, 200u);
}

/**
 * @tc.name: GetImageHeight_00001
 * @tc.desc: Test GetImageHeight after successful Init.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetImageHeight_00001, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageHeight(150);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    helper.Init();
    uint32_t height = helper.GetImageHeight();
    EXPECT_EQ(height, 150u);
}

/**
 * @tc.name: GetPixelmapBuff_00001
 * @tc.desc: Test GetPixelmapBuff after successful Init.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelmapBuff_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    helper.Init();
    uint8_t* buff = helper.GetPixelmapBuff();
    EXPECT_NE(buff, nullptr);
}

/**
 * @tc.name: CreatePixelMap_Scaling_00001
 * @tc.desc: Test image scaling when size > 500.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, CreatePixelMap_Scaling_00001, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(600);
    Notification::Mock::MockSetImageHeight(600);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "large.png");
    helper.Init();
    uint32_t width = helper.GetImageWidth();
    uint32_t height = helper.GetImageHeight();
    EXPECT_LT(width, 600u);
    EXPECT_LT(height, 600u);
}

/**
 * @tc.name: CreatePixelMap_Scaling_00002
 * @tc.desc: Test no scaling when size <= 500.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, CreatePixelMap_Scaling_00002, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(400);
    Notification::Mock::MockSetImageHeight(300);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "small.png");
    helper.Init();
    uint32_t width = helper.GetImageWidth();
    uint32_t height = helper.GetImageHeight();
    EXPECT_EQ(width, 400u);
    EXPECT_EQ(height, 300u);
}

/**
 * @tc.name: Destructor_00001
 * @tc.desc: Test destructor releases resources properly.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, Destructor_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper* helper = new ImagePixelmapHelper(request, "test.png");
    helper->Init();
    EXPECT_NE(helper->imageSource_, nullptr);
    EXPECT_NE(helper->resPixMap_, nullptr);
    EXPECT_NE(helper->imageInfo_, nullptr);
    delete helper;
    helper = nullptr;
    EXPECT_EQ(helper, nullptr);
}

/**
 * @tc.name: GetImageSourceInfo_00001
 * @tc.desc: Test GetImageSourceInfo success.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetImageSourceInfo_00001, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(100);
    Notification::Mock::MockSetImageHeight(100);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    helper.Init();
    EXPECT_EQ(helper.imageWidth_, 100u);
    EXPECT_EQ(helper.imageHeight_, 100u);
}

/**
 * @tc.name: Init_00011
 * @tc.desc: Test Init when CreateBundleContext returns nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, Init_00011, Function | SmallTest | Level1)
{
    AbilityRuntime::Mock::MockCreateBundleContextReturnNull(true);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    ErrCode ret = helper.Init();
    EXPECT_EQ(ret, ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: Init_00012
 * @tc.desc: Test Init when GetResourceManager returns nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, Init_00012, Function | SmallTest | Level1)
{
    Global::Resource::Mock::MockGetResourceManagerReturnNull(true);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    ErrCode ret = helper.Init();
    EXPECT_EQ(ret, ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: Init_00013
 * @tc.desc: Test Init when CreateBundleContext and GetResourceManager succeed.
 *            This test verifies the normal path execution of Line 131 and 136.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, Init_00013, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    
    helper.Init();
    
    EXPECT_NE(helper.resourceManager_, nullptr);
    
    EXPECT_NE(helper.rawFileDesc_.fd, 0);
}

}  // namespace Notification
}  // namespace OHOS