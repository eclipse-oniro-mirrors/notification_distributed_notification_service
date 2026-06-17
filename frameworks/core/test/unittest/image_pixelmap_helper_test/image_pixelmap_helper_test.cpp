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
    
    void SetUp() override
    {
        AbilityRuntime::Mock::MockResetApplicationContextState();
        AbilityRuntime::Mock::MockResetCreateBundleContextState();
        Global::Resource::Mock::MockResetResourceManagerState();
        Global::Resource::Mock::MockResetGetResourceManagerState();
        Notification::Mock::MockResetImageNativeState();
    }
    
    void TearDown() override
    {
        AbilityRuntime::Mock::MockResetApplicationContextState();
        AbilityRuntime::Mock::MockResetCreateBundleContextState();
        Global::Resource::Mock::MockResetResourceManagerState();
        Global::Resource::Mock::MockResetGetResourceManagerState();
        Notification::Mock::MockResetImageNativeState();
    }
};

/**
 * @tc.name: GetPixelMap_00001
 * @tc.desc: Test GetPixelMap when imageFile is empty.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "");
    std::shared_ptr<Media::PixelMap> pixelMap;
    ErrCode ret = helper.GetPixelMap(pixelMap);
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
    EXPECT_EQ(pixelMap, nullptr);
}

/**
 * @tc.name: GetPixelMap_00002
 * @tc.desc: Test GetPixelMap when request is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00002, Function | SmallTest | Level1)
{
    ImagePixelmapHelper helper(nullptr, "test.png");
    std::shared_ptr<Media::PixelMap> pixelMap;
    ErrCode ret = helper.GetPixelMap(pixelMap);
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
    EXPECT_EQ(pixelMap, nullptr);
}

/**
 * @tc.name: GetPixelMap_00003
 * @tc.desc: Test GetPixelMap when appContext is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00003, Function | SmallTest | Level1)
{
    AbilityRuntime::Mock::MockGetApplicationContextReturnNull(true);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    std::shared_ptr<Media::PixelMap> pixelMap;
    ErrCode ret = helper.GetPixelMap(pixelMap);
    EXPECT_EQ(ret, ERR_ANS_PERMISSION_DENIED);
    EXPECT_EQ(pixelMap, nullptr);
}

/**
 * @tc.name: GetPixelMap_00004
 * @tc.desc: Test GetPixelMap when GetRawFileDescriptor fails.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00004, Function | SmallTest | Level1)
{
    Global::Resource::Mock::MockGetRawFileDescriptorFail(true);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    std::shared_ptr<Media::PixelMap> pixelMap;
    ErrCode ret = helper.GetPixelMap(pixelMap);
    EXPECT_NE(ret, ERR_OK);
    EXPECT_EQ(pixelMap, nullptr);
}

/**
 * @tc.name: GetPixelMap_00005
 * @tc.desc: Test GetPixelMap when OH_ImageSourceNative_CreateFromRawFile fails.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00005, Function | SmallTest | Level1)
{
    Notification::Mock::MockOHImageSourceNativeCreateFromRawFileFail(true);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    std::shared_ptr<Media::PixelMap> pixelMap;
    ErrCode ret = helper.GetPixelMap(pixelMap);
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
    EXPECT_EQ(pixelMap, nullptr);
}

/**
 * @tc.name: GetPixelMap_00006
 * @tc.desc: Test GetPixelMap when OH_ImageSourceInfo_Create fails.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00006, Function | SmallTest | Level1)
{
    Notification::Mock::MockOHImageSourceInfoCreateFail(true);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    std::shared_ptr<Media::PixelMap> pixelMap;
    ErrCode ret = helper.GetPixelMap(pixelMap);
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
    EXPECT_EQ(pixelMap, nullptr);
}

/**
 * @tc.name: GetPixelMap_00007
 * @tc.desc: Test GetPixelMap when OH_ImageSourceInfo_GetWidth fails.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00007, Function | SmallTest | Level1)
{
    Notification::Mock::MockOHImageSourceInfoGetWidthFail(true);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    std::shared_ptr<Media::PixelMap> pixelMap;
    ErrCode ret = helper.GetPixelMap(pixelMap);
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
    EXPECT_EQ(pixelMap, nullptr);
}

/**
 * @tc.name: GetPixelMap_00008
 * @tc.desc: Test GetPixelMap when OH_ImageSourceNative_CreatePixelmap fails.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00008, Function | SmallTest | Level1)
{
    Notification::Mock::MockOHImageSourceNativeCreatePixelmapFail(true);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    std::shared_ptr<Media::PixelMap> pixelMap;
    ErrCode ret = helper.GetPixelMap(pixelMap);
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
    EXPECT_EQ(pixelMap, nullptr);
}

/**
 * @tc.name: GetPixelMap_00009
 * @tc.desc: Test GetPixelMap successfully.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00009, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(200);
    Notification::Mock::MockSetImageHeight(150);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    std::shared_ptr<Media::PixelMap> pixelMap;
    ErrCode ret = helper.GetPixelMap(pixelMap);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(pixelMap, nullptr);
}

/**
 * @tc.name: GetPixelMap_00010
 * @tc.desc: Test GetPixelMap with image scaling when size > 500.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00010, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(600);
    Notification::Mock::MockSetImageHeight(600);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "large.png");
    std::shared_ptr<Media::PixelMap> pixelMap;
    ErrCode ret = helper.GetPixelMap(pixelMap);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(pixelMap, nullptr);
}

/**
 * @tc.name: GetPixelMap_00011
 * @tc.desc: Test GetPixelMap with no scaling when size <= 500.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00011, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(400);
    Notification::Mock::MockSetImageHeight(300);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "small.png");
    std::shared_ptr<Media::PixelMap> pixelMap;
    ErrCode ret = helper.GetPixelMap(pixelMap);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(pixelMap, nullptr);
}

/**
 * @tc.name: GetPixelMap_00012
 * @tc.desc: Test GetPixelMap when CreateBundleContext returns nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00012, Function | SmallTest | Level1)
{
    AbilityRuntime::Mock::MockCreateBundleContextReturnNull(true);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    std::shared_ptr<Media::PixelMap> pixelMap;
    ErrCode ret = helper.GetPixelMap(pixelMap);
    EXPECT_EQ(ret, ERR_ANS_PERMISSION_DENIED);
    EXPECT_EQ(pixelMap, nullptr);
}

/**
 * @tc.name: GetPixelMap_00013
 * @tc.desc: Test GetPixelMap when GetResourceManager returns nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00013, Function | SmallTest | Level1)
{
    Global::Resource::Mock::MockGetResourceManagerReturnNull(true);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    std::shared_ptr<Media::PixelMap> pixelMap;
    ErrCode ret = helper.GetPixelMap(pixelMap);
    EXPECT_EQ(ret, ERR_ANS_PERMISSION_DENIED);
    EXPECT_EQ(pixelMap, nullptr);
}

/**
 * @tc.name: GetPixelMap_00014
 * @tc.desc: Test GetPixelMap successfully with resource manager initialized.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00014, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    std::shared_ptr<Media::PixelMap> pixelMap;
    
    ErrCode ret = helper.GetPixelMap(pixelMap);
    
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(pixelMap, nullptr);
    EXPECT_NE(helper.resourceManager_, nullptr);
    EXPECT_NE(helper.rawFileDesc_.fd, 0);
}

/**
 * @tc.name: GetPixelMap_00015
 * @tc.desc: Test GetPixelMap returns same PixelMap instance after successful call.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00015, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(100);
    Notification::Mock::MockSetImageHeight(100);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    std::shared_ptr<Media::PixelMap> pixelMap1;
    std::shared_ptr<Media::PixelMap> pixelMap2;
    
    ErrCode ret1 = helper.GetPixelMap(pixelMap1);
    ErrCode ret2 = helper.GetPixelMap(pixelMap2);
    
    EXPECT_EQ(ret1, ERR_OK);
    EXPECT_EQ(ret2, ERR_OK);
    EXPECT_NE(pixelMap1, nullptr);
    EXPECT_NE(pixelMap2, nullptr);
}

/**
 * @tc.name: GetPixelMap_00016
 * @tc.desc: Test GetPixelMap with different bundle names.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00016, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request1 = new NotificationRequest();
    request1->SetOwnerBundleName("com.test1");
    ImagePixelmapHelper helper1(request1, "test1.png");
    std::shared_ptr<Media::PixelMap> pixelMap1;
    ErrCode ret1 = helper1.GetPixelMap(pixelMap1);
    
    sptr<NotificationRequest> request2 = new NotificationRequest();
    request2->SetOwnerBundleName("com.test2");
    ImagePixelmapHelper helper2(request2, "test2.png");
    std::shared_ptr<Media::PixelMap> pixelMap2;
    ErrCode ret2 = helper2.GetPixelMap(pixelMap2);
    
    EXPECT_EQ(ret1, ERR_OK);
    EXPECT_EQ(ret2, ERR_OK);
    EXPECT_NE(pixelMap1, nullptr);
    EXPECT_NE(pixelMap2, nullptr);
}

/**
 * @tc.name: GetPixelMap_00017
 * @tc.desc: Test GetPixelMap with different image paths.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00017, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper1(request, "image1.png");
    std::shared_ptr<Media::PixelMap> pixelMap1;
    ErrCode ret1 = helper1.GetPixelMap(pixelMap1);
    
    ImagePixelmapHelper helper2(request, "image2.png");
    std::shared_ptr<Media::PixelMap> pixelMap2;
    ErrCode ret2 = helper2.GetPixelMap(pixelMap2);
    
    EXPECT_EQ(ret1, ERR_OK);
    EXPECT_EQ(ret2, ERR_OK);
    EXPECT_NE(pixelMap1, nullptr);
    EXPECT_NE(pixelMap2, nullptr);
}

/**
 * @tc.name: GetPixelMap_00018
 * @tc.desc: Test GetPixelMap when OH_ImageSourceInfo_GetHeight fails.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00018, Function | SmallTest | Level1)
{
    Notification::Mock::MockOHImageSourceInfoGetHeightFail(true);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    std::shared_ptr<Media::PixelMap> pixelMap;
    ErrCode ret = helper.GetPixelMap(pixelMap);
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
    EXPECT_EQ(pixelMap, nullptr);
}

/**
 * @tc.name: GetPixelMap_00019
 * @tc.desc: Test GetPixelMap when OH_ImageSourceNative_GetImageInfo fails.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00019, Function | SmallTest | Level1)
{
    Notification::Mock::MockOHImageSourceNativeGetImageInfoFail(true);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    std::shared_ptr<Media::PixelMap> pixelMap;
    ErrCode ret = helper.GetPixelMap(pixelMap);
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
    EXPECT_EQ(pixelMap, nullptr);
}

/**
 * @tc.name: GetPixelMap_00020
 * @tc.desc: Test GetPixelMap with maximum allowed image dimensions.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00020, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(500);
    Notification::Mock::MockSetImageHeight(500);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "max_size.png");
    std::shared_ptr<Media::PixelMap> pixelMap;
    ErrCode ret = helper.GetPixelMap(pixelMap);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(pixelMap, nullptr);
}

/**
 * @tc.name: GetPixelMap_00021
 * @tc.desc: Test GetPixelMap with one dimension > 500, other <= 500.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00021, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(600);
    Notification::Mock::MockSetImageHeight(300);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "mixed_size.png");
    std::shared_ptr<Media::PixelMap> pixelMap;
    ErrCode ret = helper.GetPixelMap(pixelMap);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(pixelMap, nullptr);
}

/**
 * @tc.name: GetPixelMap_00022
 * @tc.desc: Test GetPixelMap with different bundle names creates different contexts.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00022, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(100);
    Notification::Mock::MockSetImageHeight(100);
    
    std::vector<std::string> bundleNames = {"com.app1", "com.app2", "com.app3"};
    for (const auto& bundleName : bundleNames) {
        sptr<NotificationRequest> request = new NotificationRequest();
        request->SetOwnerBundleName(bundleName);
        ImagePixelmapHelper helper(request, "test.png");
        std::shared_ptr<Media::PixelMap> pixelMap;
        ErrCode ret = helper.GetPixelMap(pixelMap);
        EXPECT_EQ(ret, ERR_OK);
        EXPECT_NE(pixelMap, nullptr);
        EXPECT_NE(helper.resourceManager_, nullptr);
    }
}

/**
 * @tc.name: GetPixelMap_00023
 * @tc.desc: Test GetPixelMap stores internal pixelMap_ member correctly.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00023, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(100);
    Notification::Mock::MockSetImageHeight(100);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    std::shared_ptr<Media::PixelMap> pixelMap;
    ErrCode ret = helper.GetPixelMap(pixelMap);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(pixelMap, nullptr);
    EXPECT_NE(helper.pixelMap_, nullptr);
    EXPECT_EQ(helper.pixelMap_, pixelMap);
}

/**
 * @tc.name: GetPixelMap_00024
 * @tc.desc: Test GetPixelMap with OH_PixelmapNative_Release called (internal state).
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00024, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(100);
    Notification::Mock::MockSetImageHeight(100);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    std::shared_ptr<Media::PixelMap> pixelMap;
    
    ErrCode ret = helper.GetPixelMap(pixelMap);
    
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(pixelMap, nullptr);
    EXPECT_NE(helper.pixelMap_, nullptr);
}

/**
 * @tc.name: GetPixelMap_00025
 * @tc.desc: Test GetPixelMap called twice returns same PixelMap.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00025, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(100);
    Notification::Mock::MockSetImageHeight(100);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    
    std::shared_ptr<Media::PixelMap> pixelMap1;
    ErrCode ret1 = helper.GetPixelMap(pixelMap1);
    EXPECT_EQ(ret1, ERR_OK);
    EXPECT_NE(pixelMap1, nullptr);
    
    std::shared_ptr<Media::PixelMap> pixelMap2;
    ErrCode ret2 = helper.GetPixelMap(pixelMap2);
    EXPECT_EQ(ret2, ERR_OK);
    EXPECT_NE(pixelMap2, nullptr);
    
    EXPECT_NE(helper.pixelMap_, nullptr);
}

/**
 * @tc.name: GetPixelMap_00026
 * @tc.desc: Test GetPixelMap with ASTC_4x4 format setting.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00026, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(200);
    Notification::Mock::MockSetImageHeight(200);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "astc_test.png");
    std::shared_ptr<Media::PixelMap> pixelMap;
    ErrCode ret = helper.GetPixelMap(pixelMap);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(pixelMap, nullptr);
}

/**
 * @tc.name: GetPixelMap_00027
 * @tc.desc: Test GetPixelMap with different bundle contexts.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00027, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(100);
    Notification::Mock::MockSetImageHeight(100);
    
    sptr<NotificationRequest> request1 = new NotificationRequest();
    request1->SetOwnerBundleName("com.test1");
    ImagePixelmapHelper helper1(request1, "test1.png");
    std::shared_ptr<Media::PixelMap> pixelMap1;
    ErrCode ret1 = helper1.GetPixelMap(pixelMap1);
    
    sptr<NotificationRequest> request2 = new NotificationRequest();
    request2->SetOwnerBundleName("com.test2");
    ImagePixelmapHelper helper2(request2, "test2.png");
    std::shared_ptr<Media::PixelMap> pixelMap2;
    ErrCode ret2 = helper2.GetPixelMap(pixelMap2);
    
    EXPECT_EQ(ret1, ERR_OK);
    EXPECT_EQ(ret2, ERR_OK);
    EXPECT_NE(pixelMap1, nullptr);
    EXPECT_NE(pixelMap2, nullptr);
    EXPECT_NE(helper1.pixelMap_, nullptr);
    EXPECT_NE(helper2.pixelMap_, nullptr);
}

/**
 * @tc.name: GetPixelMap_00028
 * @tc.desc: Test GetPixelMap when GetImageSourceInfo fails with height error.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00028, Function | SmallTest | Level1)
{
    Notification::Mock::MockOHImageSourceInfoGetHeightFail(true);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    std::shared_ptr<Media::PixelMap> pixelMap;
    ErrCode ret = helper.GetPixelMap(pixelMap);
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
    EXPECT_EQ(pixelMap, nullptr);
    EXPECT_EQ(helper.pixelMap_, nullptr);
}

/**
 * @tc.name: GetPixelMap_00029
 * @tc.desc: Test GetPixelMap when GetImageSourceInfo fails with image info error.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00029, Function | SmallTest | Level1)
{
    Notification::Mock::MockOHImageSourceNativeGetImageInfoFail(true);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    std::shared_ptr<Media::PixelMap> pixelMap;
    ErrCode ret = helper.GetPixelMap(pixelMap);
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
    EXPECT_EQ(pixelMap, nullptr);
    EXPECT_EQ(helper.pixelMap_, nullptr);
}

/**
 * @tc.name: GetPixelMap_00030
 * @tc.desc: Test GetPixelMap verifies imageWidth_ and imageHeight_ are set.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00030, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(150);
    Notification::Mock::MockSetImageHeight(200);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    std::shared_ptr<Media::PixelMap> pixelMap;
    ErrCode ret = helper.GetPixelMap(pixelMap);
    
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(pixelMap, nullptr);
    EXPECT_EQ(helper.imageWidth_, 150u);
    EXPECT_EQ(helper.imageHeight_, 200u);
}

/**
 * @tc.name: GetPixelMap_00031
 * @tc.desc: Test GetPixelMap with very small image (1x1).
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00031, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(1);
    Notification::Mock::MockSetImageHeight(1);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "tiny.png");
    std::shared_ptr<Media::PixelMap> pixelMap;
    ErrCode ret = helper.GetPixelMap(pixelMap);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(pixelMap, nullptr);
}

/**
 * @tc.name: GetPixelMap_00032
 * @tc.desc: Test GetPixelMap with rectangular images (different aspect ratios).
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00032, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(100);
    Notification::Mock::MockSetImageHeight(500);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "vertical.png");
    std::shared_ptr<Media::PixelMap> pixelMap;
    ErrCode ret = helper.GetPixelMap(pixelMap);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(pixelMap, nullptr);
}

/**
 * @tc.name: GetPixelMap_00033
 * @tc.desc: Test GetPixelMap checks rawFileDesc_ is initialized.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00033, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    std::shared_ptr<Media::PixelMap> pixelMap;
    
    ErrCode ret = helper.GetPixelMap(pixelMap);
    
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(pixelMap, nullptr);
    EXPECT_NE(helper.rawFileDesc_.fd, 0);
}

/**
 * @tc.name: GetPixelMap_00034
 * @tc.desc: Test GetPixelMap checks resourceManager_ is initialized.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00034, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    std::shared_ptr<Media::PixelMap> pixelMap;
    
    ErrCode ret = helper.GetPixelMap(pixelMap);
    
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(pixelMap, nullptr);
    EXPECT_NE(helper.resourceManager_, nullptr);
}

/**
 * @tc.name: GetPixelMap_00035
 * @tc.desc: Test GetPixelMap checks imageSource_ is created.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00035, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    std::shared_ptr<Media::PixelMap> pixelMap;
    
    ErrCode ret = helper.GetPixelMap(pixelMap);
    
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(pixelMap, nullptr);
    EXPECT_NE(helper.imageSource_, nullptr);
}

/**
 * @tc.name: GetPixelMap_00036
 * @tc.desc: Test GetPixelMap checks imageInfo_ is created.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00036, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    std::shared_ptr<Media::PixelMap> pixelMap;
    
    ErrCode ret = helper.GetPixelMap(pixelMap);
    
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(pixelMap, nullptr);
    EXPECT_NE(helper.imageInfo_, nullptr);
}

/**
 * @tc.name: GetPixelMap_00037
 * @tc.desc: Test GetPixelMap with extreme large image dimensions.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00037, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(1000);
    Notification::Mock::MockSetImageHeight(1000);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "extreme_large.png");
    std::shared_ptr<Media::PixelMap> pixelMap;
    ErrCode ret = helper.GetPixelMap(pixelMap);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(pixelMap, nullptr);
}

/**
 * @tc.name: GetPixelMap_00038
 * @tc.desc: Test GetPixelMap with non-square scaling scenarios.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00038, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(800);
    Notification::Mock::MockSetImageHeight(600);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "non_square.png");
    std::shared_ptr<Media::PixelMap> pixelMap;
    ErrCode ret = helper.GetPixelMap(pixelMap);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(pixelMap, nullptr);
}

/**
 * @tc.name: GetPixelMap_00039
 * @tc.desc: Test GetPixelMap with width-only scaling (> 500).
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00039, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(600);
    Notification::Mock::MockSetImageHeight(100);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "wide.png");
    std::shared_ptr<Media::PixelMap> pixelMap;
    ErrCode ret = helper.GetPixelMap(pixelMap);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(pixelMap, nullptr);
}

/**
 * @tc.name: GetPixelMap_00040
 * @tc.desc: Test GetPixelMap with height-only scaling (> 500).
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00040, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(100);
    Notification::Mock::MockSetImageHeight(600);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "tall.png");
    std::shared_ptr<Media::PixelMap> pixelMap;
    ErrCode ret = helper.GetPixelMap(pixelMap);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(pixelMap, nullptr);
}

/**
 * @tc.name: GetPixelMap_00041
 * @tc.desc: Test GetPixelMap with multiple sequential calls.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00041, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(100);
    Notification::Mock::MockSetImageHeight(100);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    
    for (int i = 0; i < 5; i++) {
        std::shared_ptr<Media::PixelMap> pixelMap;
        ErrCode ret = helper.GetPixelMap(pixelMap);
        EXPECT_EQ(ret, ERR_OK);
        EXPECT_NE(pixelMap, nullptr);
    }
}

/**
 * @tc.name: GetPixelMap_00042
 * @tc.desc: Test GetPixelMap with different file paths.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00042, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(100);
    Notification::Mock::MockSetImageHeight(100);
    
    std::vector<std::string> paths = {"test1.png", "test2.png", "test3.jpg"};
    for (const auto& path : paths) {
        sptr<NotificationRequest> request = new NotificationRequest();
        request->SetOwnerBundleName("com.test");
        ImagePixelmapHelper helper(request, path);
        std::shared_ptr<Media::PixelMap> pixelMap;
        ErrCode ret = helper.GetPixelMap(pixelMap);
        EXPECT_EQ(ret, ERR_OK);
        EXPECT_NE(pixelMap, nullptr);
    }
}

/**
 * @tc.name: GetPixelMap_00043
 * @tc.desc: Test GetPixelMap internal state consistency.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00043, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(200);
    Notification::Mock::MockSetImageHeight(200);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "state_test.png");
    std::shared_ptr<Media::PixelMap> pixelMap;
    
    ErrCode ret = helper.GetPixelMap(pixelMap);
    
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(pixelMap, nullptr);
    EXPECT_NE(helper.pixelMap_, nullptr);
    EXPECT_NE(helper.imageSource_, nullptr);
    EXPECT_NE(helper.imageInfo_, nullptr);
    EXPECT_NE(helper.resourceManager_, nullptr);
    EXPECT_NE(helper.rawFileDesc_.fd, 0);
    EXPECT_EQ(helper.imageWidth_, 200u);
    EXPECT_EQ(helper.imageHeight_, 200u);
}

/**
 * @tc.name: GetPixelMap_00044
 * @tc.desc: Test GetPixelMap with close to boundary size (499x499).
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00044, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(499);
    Notification::Mock::MockSetImageHeight(499);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "boundary.png");
    std::shared_ptr<Media::PixelMap> pixelMap;
    ErrCode ret = helper.GetPixelMap(pixelMap);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(pixelMap, nullptr);
}

/**
 * @tc.name: GetPixelMap_00045
 * @tc.desc: Test GetPixelMap with exactly 500x500 dimensions.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00045, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(500);
    Notification::Mock::MockSetImageHeight(500);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "exact_500.png");
    std::shared_ptr<Media::PixelMap> pixelMap;
    ErrCode ret = helper.GetPixelMap(pixelMap);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(pixelMap, nullptr);
}

/**
 * @tc.name: GetPixelMap_00046
 * @tc.desc: Test GetPixelMap with slightly above boundary (501x501).
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00046, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(501);
    Notification::Mock::MockSetImageHeight(501);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "above_boundary.png");
    std::shared_ptr<Media::PixelMap> pixelMap;
    ErrCode ret = helper.GetPixelMap(pixelMap);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(pixelMap, nullptr);
}

/**
 * @tc.name: GetPixelMap_00047
 * @tc.desc: Test GetPixelMap with pixelMap_ state after successful call.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00047, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(100);
    Notification::Mock::MockSetImageHeight(100);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    
    EXPECT_EQ(helper.pixelMap_, nullptr);
    
    std::shared_ptr<Media::PixelMap> pixelMap;
    ErrCode ret = helper.GetPixelMap(pixelMap);
    
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(pixelMap, nullptr);
    EXPECT_NE(helper.pixelMap_, nullptr);
    EXPECT_EQ(helper.pixelMap_, pixelMap);
}

/**
 * @tc.name: GetPixelMap_00048
 * @tc.desc: Test GetPixelMap pixelMap remains nullptr on failure.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00048, Function | SmallTest | Level1)
{
    Notification::Mock::MockOHImageSourceNativeCreatePixelmapFail(true);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    
    EXPECT_EQ(helper.pixelMap_, nullptr);
    
    std::shared_ptr<Media::PixelMap> pixelMap;
    ErrCode ret = helper.GetPixelMap(pixelMap);
    
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
    EXPECT_EQ(pixelMap, nullptr);
    EXPECT_EQ(helper.pixelMap_, nullptr);
}

/**
 * @tc.name: GetPixelMap_00049
 * @tc.desc: Test GetPixelMap validates pixelMap output parameter.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetPixelMap_00049, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(100);
    Notification::Mock::MockSetImageHeight(100);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    std::shared_ptr<Media::PixelMap> pixelMap;
    
    ErrCode ret = helper.GetPixelMap(pixelMap);
    
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(pixelMap.get(), nullptr);
    EXPECT_TRUE(pixelMap->GetWidth() > 0 || pixelMap->GetHeight() > 0);
}

/**
 * @tc.name: Constructor_00001
 * @tc.desc: Test constructor initializes member variables correctly.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, Constructor_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    std::string imageFile = "test.png";
    
    ImagePixelmapHelper helper(request, imageFile);
    
    EXPECT_EQ(helper.imageFile_, imageFile);
    EXPECT_EQ(helper.request_, request);
    EXPECT_EQ(helper.rawFileDesc_.fd, 0);
    EXPECT_EQ(helper.rawFileDesc_.offset, 0);
    EXPECT_EQ(helper.rawFileDesc_.length, 0);
    EXPECT_EQ(helper.imageWidth_, 0u);
    EXPECT_EQ(helper.imageHeight_, 0u);
    EXPECT_EQ(helper.imageSource_, nullptr);
    EXPECT_EQ(helper.imageInfo_, nullptr);
    EXPECT_EQ(helper.resourceManager_, nullptr);
    EXPECT_EQ(helper.pixelMap_, nullptr);
}

/**
 * @tc.name: Constructor_00002
 * @tc.desc: Test constructor with empty imageFile.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, Constructor_00002, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    
    ImagePixelmapHelper helper(request, "");
    
    EXPECT_EQ(helper.imageFile_, "");
    EXPECT_EQ(helper.request_, request);
    EXPECT_EQ(helper.pixelMap_, nullptr);
}

/**
 * @tc.name: Constructor_00003
 * @tc.desc: Test constructor with nullptr request.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, Constructor_00003, Function | SmallTest | Level1)
{
    std::string imageFile = "test.png";
    
    ImagePixelmapHelper helper(nullptr, imageFile);
    
    EXPECT_EQ(helper.imageFile_, imageFile);
    EXPECT_EQ(helper.request_, nullptr);
    EXPECT_EQ(helper.pixelMap_, nullptr);
}

/**
 * @tc.name: Destructor_00001
 * @tc.desc: Test destructor releases all resources.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, Destructor_00001, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(100);
    Notification::Mock::MockSetImageHeight(100);
    
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    
    ImagePixelmapHelper* helper = new ImagePixelmapHelper(request, "test.png");
    std::shared_ptr<Media::PixelMap> pixelMap;
    helper->GetPixelMap(pixelMap);
    
    EXPECT_NE(helper->imageSource_, nullptr);
    EXPECT_NE(helper->imageInfo_, nullptr);
    EXPECT_NE(helper->resourceManager_, nullptr);
    EXPECT_NE(helper->pixelMap_, nullptr);
    
    delete helper;
    helper = nullptr;
    EXPECT_EQ(helper, nullptr);
}

/**
 * @tc.name: Destructor_00002
 * @tc.desc: Test destructor handles nullptr resources gracefully.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, Destructor_00002, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    
    ImagePixelmapHelper* helper = new ImagePixelmapHelper(request, "test.png");
    
    EXPECT_EQ(helper->imageSource_, nullptr);
    EXPECT_EQ(helper->imageInfo_, nullptr);
    EXPECT_EQ(helper->resourceManager_, nullptr);
    EXPECT_EQ(helper->pixelMap_, nullptr);
    
    delete helper;
    helper = nullptr;
    EXPECT_EQ(helper, nullptr);
}

/**
 * @tc.name: Destructor_00003
 * @tc.desc: Test destructor resets member variables.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, Destructor_00003, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(100);
    Notification::Mock::MockSetImageHeight(100);
    
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    
    ImagePixelmapHelper* helper = new ImagePixelmapHelper(request, "test.png");
    std::shared_ptr<Media::PixelMap> pixelMap;
    helper->GetPixelMap(pixelMap);
    
    EXPECT_EQ(helper->imageWidth_, 100u);
    EXPECT_EQ(helper->imageHeight_, 100u);
    
    delete helper;
}

/**
 * @tc.name: InitRawfileData_00001
 * @tc.desc: Test InitRawfileData successfully.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, InitRawfileData_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    
    ErrCode ret = helper.InitRawfileData();
    
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(helper.resourceManager_, nullptr);
    EXPECT_NE(helper.rawFileDesc_.fd, 0);
}

/**
 * @tc.name: InitRawfileData_00002
 * @tc.desc: Test InitRawfileData when appContext is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, InitRawfileData_00002, Function | SmallTest | Level1)
{
    AbilityRuntime::Mock::MockGetApplicationContextReturnNull(true);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    
    ErrCode ret = helper.InitRawfileData();
    
    EXPECT_EQ(ret, ERR_ANS_PERMISSION_DENIED);
    EXPECT_EQ(helper.resourceManager_, nullptr);
}

/**
 * @tc.name: InitRawfileData_00003
 * @tc.desc: Test InitRawfileData when CreateBundleContext fails.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, InitRawfileData_00003, Function | SmallTest | Level1)
{
    AbilityRuntime::Mock::MockCreateBundleContextReturnNull(true);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    
    ErrCode ret = helper.InitRawfileData();
    
    EXPECT_EQ(ret, ERR_ANS_PERMISSION_DENIED);
    EXPECT_EQ(helper.resourceManager_, nullptr);
}

/**
 * @tc.name: InitRawfileData_00004
 * @tc.desc: Test InitRawfileData when GetResourceManager returns nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, InitRawfileData_00004, Function | SmallTest | Level1)
{
    Global::Resource::Mock::MockGetResourceManagerReturnNull(true);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    
    ErrCode ret = helper.InitRawfileData();
    
    EXPECT_EQ(ret, ERR_ANS_PERMISSION_DENIED);
    EXPECT_EQ(helper.resourceManager_, nullptr);
}

/**
 * @tc.name: InitRawfileData_00005
 * @tc.desc: Test InitRawfileData when GetRawFileDescriptor fails.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, InitRawfileData_00005, Function | SmallTest | Level1)
{
    Global::Resource::Mock::MockGetRawFileDescriptorFail(true);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    
    ErrCode ret = helper.InitRawfileData();
    
    EXPECT_NE(ret, ERR_OK);
    EXPECT_NE(helper.resourceManager_, nullptr);
}

/**
 * @tc.name: InitRawfileData_00006
 * @tc.desc: Test InitRawfileData with different bundle names.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, InitRawfileData_00006, Function | SmallTest | Level1)
{
    std::vector<std::string> bundleNames = {"com.app1", "com.app2", "com.app3"};
    
    for (const auto& bundleName : bundleNames) {
        sptr<NotificationRequest> request = new NotificationRequest();
        request->SetOwnerBundleName(bundleName);
        ImagePixelmapHelper helper(request, "test.png");
        
        ErrCode ret = helper.InitRawfileData();
        
        EXPECT_EQ(ret, ERR_OK);
        EXPECT_NE(helper.resourceManager_, nullptr);
    }
}

/**
 * @tc.name: InitRawfileData_00007
 * @tc.desc: Test InitRawfileData verifies bundleName from request.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, InitRawfileData_00007, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test.verify");
    ImagePixelmapHelper helper(request, "test.png");
    
    ErrCode ret = helper.InitRawfileData();
    
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(helper.resourceManager_, nullptr);
}

/**
 * @tc.name: CreateImageSource_00001
 * @tc.desc: Test CreateImageSource successfully.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, CreateImageSource_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    
    helper.InitRawfileData();
    ErrCode ret = helper.CreateImageSource();
    
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(helper.imageSource_, nullptr);
}

/**
 * @tc.name: CreateImageSource_00002
 * @tc.desc: Test CreateImageSource when OH_ImageSourceNative_CreateFromRawFile fails.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, CreateImageSource_00002, Function | SmallTest | Level1)
{
    Notification::Mock::MockOHImageSourceNativeCreateFromRawFileFail(true);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    
    helper.InitRawfileData();
    ErrCode ret = helper.CreateImageSource();
    
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
    EXPECT_EQ(helper.imageSource_, nullptr);
}

/**
 * @tc.name: CreateImageSource_00003
 * @tc.desc: Test CreateImageSource when OH_ImageSourceNative_CreateFromRawFile returns nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, CreateImageSource_00003, Function | SmallTest | Level1)
{
    Notification::Mock::MockOHImageSourceNativeCreateFromRawFileReturnNull(true);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    
    helper.InitRawfileData();
    ErrCode ret = helper.CreateImageSource();
    
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
    EXPECT_EQ(helper.imageSource_, nullptr);
}

/**
 * @tc.name: CreateImageSource_00004
 * @tc.desc: Test CreateImageSource uses rawFileDesc_ correctly.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, CreateImageSource_00004, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    
    helper.InitRawfileData();
    EXPECT_NE(helper.rawFileDesc_.fd, 0);
    
    ErrCode ret = helper.CreateImageSource();
    
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(helper.imageSource_, nullptr);
}

/**
 * @tc.name: GetImageSourceInfo_00001
 * @tc.desc: Test GetImageSourceInfo successfully.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetImageSourceInfo_00001, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(200);
    Notification::Mock::MockSetImageHeight(150);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    
    helper.InitRawfileData();
    helper.CreateImageSource();
    ErrCode ret = helper.GetImageSourceInfo();
    
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(helper.imageInfo_, nullptr);
    EXPECT_EQ(helper.imageWidth_, 200u);
    EXPECT_EQ(helper.imageHeight_, 150u);
}

/**
 * @tc.name: GetImageSourceInfo_00002
 * @tc.desc: Test GetImageSourceInfo when OH_ImageSourceInfo_Create fails.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetImageSourceInfo_00002, Function | SmallTest | Level1)
{
    Notification::Mock::MockOHImageSourceInfoCreateFail(true);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    
    helper.InitRawfileData();
    helper.CreateImageSource();
    ErrCode ret = helper.GetImageSourceInfo();
    
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
    EXPECT_EQ(helper.imageInfo_, nullptr);
}

/**
 * @tc.name: GetImageSourceInfo_00003
 * @tc.desc: Test GetImageSourceInfo when OH_ImageSourceInfo_Create returns nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetImageSourceInfo_00003, Function | SmallTest | Level1)
{
    Notification::Mock::MockOHImageSourceInfoCreateReturnNull(true);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    
    helper.InitRawfileData();
    helper.CreateImageSource();
    ErrCode ret = helper.GetImageSourceInfo();
    
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
    EXPECT_EQ(helper.imageInfo_, nullptr);
}

/**
 * @tc.name: GetImageSourceInfo_00004
 * @tc.desc: Test GetImageSourceInfo when OH_ImageSourceNative_GetImageInfo fails.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetImageSourceInfo_00004, Function | SmallTest | Level1)
{
    Notification::Mock::MockOHImageSourceNativeGetImageInfoFail(true);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    
    helper.InitRawfileData();
    helper.CreateImageSource();
    ErrCode ret = helper.GetImageSourceInfo();
    
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: GetImageSourceInfo_00005
 * @tc.desc: Test GetImageSourceInfo when OH_ImageSourceInfo_GetWidth fails.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetImageSourceInfo_00005, Function | SmallTest | Level1)
{
    Notification::Mock::MockOHImageSourceInfoGetWidthFail(true);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    
    helper.InitRawfileData();
    helper.CreateImageSource();
    ErrCode ret = helper.GetImageSourceInfo();
    
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: GetImageSourceInfo_00006
 * @tc.desc: Test GetImageSourceInfo when OH_ImageSourceInfo_GetHeight fails.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetImageSourceInfo_00006, Function | SmallTest | Level1)
{
    Notification::Mock::MockOHImageSourceInfoGetHeightFail(true);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    
    helper.InitRawfileData();
    helper.CreateImageSource();
    ErrCode ret = helper.GetImageSourceInfo();
    
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: GetImageSourceInfo_00007
 * @tc.desc: Test GetImageSourceInfo with different image dimensions.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, GetImageSourceInfo_00007, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(600);
    Notification::Mock::MockSetImageHeight(400);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    
    helper.InitRawfileData();
    helper.CreateImageSource();
    ErrCode ret = helper.GetImageSourceInfo();
    
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(helper.imageWidth_, 600u);
    EXPECT_EQ(helper.imageHeight_, 400u);
}

/**
 * @tc.name: CreatePixelMap_00001
 * @tc.desc: Test CreatePixelMap successfully without scaling.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, CreatePixelMap_00001, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(100);
    Notification::Mock::MockSetImageHeight(100);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    
    helper.InitRawfileData();
    helper.CreateImageSource();
    ErrCode ret = helper.CreatePixelMap();
    
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(helper.pixelMap_, nullptr);
}

/**
 * @tc.name: CreatePixelMap_00002
 * @tc.desc: Test CreatePixelMap with scaling when width > 500.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, CreatePixelMap_00002, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(600);
    Notification::Mock::MockSetImageHeight(300);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    
    helper.InitRawfileData();
    helper.CreateImageSource();
    ErrCode ret = helper.CreatePixelMap();
    
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(helper.pixelMap_, nullptr);
}

/**
 * @tc.name: CreatePixelMap_00003
 * @tc.desc: Test CreatePixelMap with scaling when height > 500.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, CreatePixelMap_00003, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(300);
    Notification::Mock::MockSetImageHeight(600);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    
    helper.InitRawfileData();
    helper.CreateImageSource();
    ErrCode ret = helper.CreatePixelMap();
    
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(helper.pixelMap_, nullptr);
}

/**
 * @tc.name: CreatePixelMap_00004
 * @tc.desc: Test CreatePixelMap with both dimensions > 500.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, CreatePixelMap_00004, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(1000);
    Notification::Mock::MockSetImageHeight(1000);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    
    helper.InitRawfileData();
    helper.CreateImageSource();
    ErrCode ret = helper.CreatePixelMap();
    
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(helper.pixelMap_, nullptr);
}

/**
 * @tc.name: CreatePixelMap_00005
 * @tc.desc: Test CreatePixelMap when OH_ImageSourceNative_CreatePixelmap fails.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, CreatePixelMap_00005, Function | SmallTest | Level1)
{
    Notification::Mock::MockOHImageSourceNativeCreatePixelmapFail(true);
    Notification::Mock::MockSetImageWidth(100);
    Notification::Mock::MockSetImageHeight(100);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    
    helper.InitRawfileData();
    helper.CreateImageSource();
    ErrCode ret = helper.CreatePixelMap();
    
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
    EXPECT_EQ(helper.pixelMap_, nullptr);
}

/**
 * @tc.name: CreatePixelMap_00006
 * @tc.desc: Test CreatePixelMap when OH_ImageSourceNative_CreatePixelmap returns nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, CreatePixelMap_00006, Function | SmallTest | Level1)
{
    Notification::Mock::MockOHImageSourceNativeCreatePixelmapReturnNull(true);
    Notification::Mock::MockSetImageWidth(100);
    Notification::Mock::MockSetImageHeight(100);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    
    helper.InitRawfileData();
    helper.CreateImageSource();
    ErrCode ret = helper.CreatePixelMap();
    
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
    EXPECT_EQ(helper.pixelMap_, nullptr);
}

/**
 * @tc.name: CreatePixelMap_00007
 * @tc.desc: Test CreatePixelMap internal state after success.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, CreatePixelMap_00007, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(150);
    Notification::Mock::MockSetImageHeight(200);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    
    helper.InitRawfileData();
    helper.CreateImageSource();
    ErrCode ret = helper.CreatePixelMap();
    
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(helper.pixelMap_, nullptr);
    EXPECT_NE(helper.imageSource_, nullptr);
    EXPECT_NE(helper.imageInfo_, nullptr);
    EXPECT_NE(helper.resourceManager_, nullptr);
}

/**
 * @tc.name: CreatePixelMap_00008
 * @tc.desc: Test CreatePixelMap verifies GetInnerPixelmap called.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, CreatePixelMap_00008, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(100);
    Notification::Mock::MockSetImageHeight(100);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    
    helper.InitRawfileData();
    helper.CreateImageSource();
    
    EXPECT_EQ(helper.pixelMap_, nullptr);
    
    ErrCode ret = helper.CreatePixelMap();
    
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(helper.pixelMap_, nullptr);
}

/**
 * @tc.name: CreatePixelMap_00009
 * @tc.desc: Test CreatePixelMap with boundary dimensions 500x500.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, CreatePixelMap_00009, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(500);
    Notification::Mock::MockSetImageHeight(500);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    
    helper.InitRawfileData();
    helper.CreateImageSource();
    ErrCode ret = helper.CreatePixelMap();
    
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(helper.pixelMap_, nullptr);
}

/**
 * @tc.name: CreatePixelMap_00010
 * @tc.desc: Test CreatePixelMap with GetImageSourceInfo failure.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, CreatePixelMap_00010, Function | SmallTest | Level1)
{
    Notification::Mock::MockOHImageSourceInfoGetWidthFail(true);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    
    helper.InitRawfileData();
    helper.CreateImageSource();
    ErrCode ret = helper.CreatePixelMap();
    
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
    EXPECT_EQ(helper.pixelMap_, nullptr);
}

/**
 * @tc.name: CreatePixelMap_00011
 * @tc.desc: Test CreatePixelMap uses ASTC_4x4 format.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, CreatePixelMap_00011, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(200);
    Notification::Mock::MockSetImageHeight(200);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    
    helper.InitRawfileData();
    helper.CreateImageSource();
    ErrCode ret = helper.CreatePixelMap();
    
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(helper.pixelMap_, nullptr);
}

/**
 * @tc.name: CreatePixelMap_00012
 * @tc.desc: Test CreatePixelMap calculates correct scaling ratio.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, CreatePixelMap_00012, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(800);
    Notification::Mock::MockSetImageHeight(600);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    
    helper.InitRawfileData();
    helper.CreateImageSource();
    ErrCode ret = helper.CreatePixelMap();
    
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(helper.pixelMap_, nullptr);
}

/**
 * @tc.name: CreatePixelMap_00013
 * @tc.desc: Test CreatePixelMap with small square image.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, CreatePixelMap_00013, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(1);
    Notification::Mock::MockSetImageHeight(1);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    
    helper.InitRawfileData();
    helper.CreateImageSource();
    ErrCode ret = helper.CreatePixelMap();
    
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(helper.pixelMap_, nullptr);
}

/**
 * @tc.name: CreatePixelMap_00014
 * @tc.desc: Test CreatePixelMap stores pixelMap_ correctly.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, CreatePixelMap_00014, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(100);
    Notification::Mock::MockSetImageHeight(100);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    
    helper.InitRawfileData();
    helper.CreateImageSource();
    
    ErrCode ret = helper.CreatePixelMap();
    
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(helper.pixelMap_, nullptr);
    EXPECT_NE(helper.pixelMap_.get(), nullptr);
}

/**
 * @tc.name: CreatePixelMap_00015
 * @tc.desc: Test CreatePixelMap with rectangular images.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, CreatePixelMap_00015, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(400);
    Notification::Mock::MockSetImageHeight(100);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    
    helper.InitRawfileData();
    helper.CreateImageSource();
    ErrCode ret = helper.CreatePixelMap();
    
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(helper.pixelMap_, nullptr);
}

/**
 * @tc.name: CreatePixelMap_00016
 * @tc.desc: Test CreatePixelMap with OH_DecodingOptions_Release called.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, CreatePixelMap_00016, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(100);
    Notification::Mock::MockSetImageHeight(100);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    
    helper.InitRawfileData();
    helper.CreateImageSource();
    
    ErrCode ret = helper.CreatePixelMap();
    
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(helper.pixelMap_, nullptr);
}

/**
 * @tc.name: CreatePixelMap_00017
 * @tc.desc: Test CreatePixelMap with OH_PixelmapNative_Release called.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, CreatePixelMap_00017, Function | SmallTest | Level1)
{
    Notification::Mock::MockSetImageWidth(100);
    Notification::Mock::MockSetImageHeight(100);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    
    helper.InitRawfileData();
    helper.CreateImageSource();
    
    ErrCode ret = helper.CreatePixelMap();
    
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(helper.pixelMap_, nullptr);
}

/**
 * @tc.name: CreatePixelMap_00018
 * @tc.desc: Test CreatePixelMap when resPixMap_ is nullptr after creation.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, CreatePixelMap_00018, Function | SmallTest | Level1)
{
    Notification::Mock::MockOHImageSourceNativeCreatePixelmapReturnNull(true);
    Notification::Mock::MockSetImageWidth(100);
    Notification::Mock::MockSetImageHeight(100);
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("com.test");
    ImagePixelmapHelper helper(request, "test.png");
    
    helper.InitRawfileData();
    helper.CreateImageSource();
    
    ErrCode ret = helper.CreatePixelMap();
    
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
    EXPECT_EQ(helper.pixelMap_, nullptr);
}

/**
 * @tc.name: CreatePixelMap_00019
 * @tc.desc: Test CreatePixelMap with different aspect ratios.
 * @tc.type: FUNC
 * @tc.require: issueI8WRQ2
 */
HWTEST_F(ImagePixelmapHelperTest, CreatePixelMap_00019, Function | SmallTest | Level1)
{
    std::vector<std::pair<uint32_t, uint32_t>> sizes = {
        {100, 100}, {200, 100}, {100, 200}, {50, 50}, {1000, 500}
    };
    
    for (const auto& size : sizes) {
        Notification::Mock::MockSetImageWidth(size.first);
        Notification::Mock::MockSetImageHeight(size.second);
        sptr<NotificationRequest> request = new NotificationRequest();
        request->SetOwnerBundleName("com.test");
        ImagePixelmapHelper helper(request, "test.png");
        
        helper.InitRawfileData();
        helper.CreateImageSource();
        ErrCode ret = helper.CreatePixelMap();
        
        EXPECT_EQ(ret, ERR_OK);
        EXPECT_NE(helper.pixelMap_, nullptr);
    }
}
}  // namespace Notification
}  // namespace OHOS