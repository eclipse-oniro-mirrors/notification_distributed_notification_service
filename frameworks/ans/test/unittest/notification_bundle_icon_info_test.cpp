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
#include "notification_bundle_icon_info.h"
#undef private
#undef protected

using namespace testing::ext;
namespace OHOS {
namespace Notification {
namespace {
constexpr int32_t ICON_SIZE = 8;
constexpr int32_t TEST_UID = 100;
constexpr int32_t TEST_APP_INDEX = 0;

inline void TestSetImageInfo(const std::shared_ptr<Media::PixelMap>& pixelMap, int32_t width, int32_t height)
{
    Media::ImageInfo info;
    info.size.width = width;
    info.size.height = height;
    info.pixelFormat = Media::PixelFormat::ARGB_8888;
    info.colorSpace = Media::ColorSpace::SRGB;
    pixelMap->SetImageInfo(info);
}

inline void TestSetPixels(const std::shared_ptr<Media::PixelMap>& pixelMap, int32_t width, int32_t height)
{
    const int32_t PIXEL_BYTES = 4;
    int32_t rowDataSize = width * PIXEL_BYTES;
    uint32_t bufferSize = rowDataSize * height;
    void *buffer = malloc(bufferSize);
    if (buffer != nullptr) {
        pixelMap->SetPixelsAddr(buffer, nullptr, bufferSize, Media::AllocatorType::HEAP_ALLOC, nullptr);
    }
}

inline std::shared_ptr<Media::PixelMap> TestMakePixelMap(int32_t width, int32_t height)
{
    std::shared_ptr<Media::PixelMap> pixelMap = std::make_shared<Media::PixelMap>();
    if (pixelMap == nullptr) {
        return nullptr;
    }
    TestSetImageInfo(pixelMap, width, height);
    TestSetPixels(pixelMap, width, height);
    return pixelMap;
}
}  // namespace

class NotificationBundleIconInfoTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: Constructor_00001
 * @tc.desc: Test NotificationBundleIconInfo constructor and getters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationBundleIconInfoTest, Constructor_00001, Function | SmallTest | Level1)
{
    auto icon = TestMakePixelMap(ICON_SIZE, ICON_SIZE);
    ASSERT_NE(icon, nullptr);
    auto bundleIconInfo = std::make_shared<NotificationBundleIconInfo>("bundle.test", TEST_UID, TEST_APP_INDEX, icon);
    ASSERT_NE(bundleIconInfo, nullptr);

    EXPECT_EQ(bundleIconInfo->GetBundleName(), "bundle.test");
    EXPECT_EQ(bundleIconInfo->GetUid(), TEST_UID);
    EXPECT_EQ(bundleIconInfo->GetAppIndex(), TEST_APP_INDEX);
    EXPECT_NE(bundleIconInfo->GetIcon(), nullptr);
}

/**
 * @tc.name: SetAndGet_00001
 * @tc.desc: Test setters and getters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationBundleIconInfoTest, SetAndGet_00001, Function | SmallTest | Level1)
{
    auto bundleIconInfo = std::make_shared<NotificationBundleIconInfo>();
    ASSERT_NE(bundleIconInfo, nullptr);

    bundleIconInfo->SetBundleName("bundle.setter");
    bundleIconInfo->SetUid(TEST_UID);
    bundleIconInfo->SetAppIndex(TEST_APP_INDEX);
    auto icon = TestMakePixelMap(ICON_SIZE, ICON_SIZE);
    ASSERT_NE(icon, nullptr);
    bundleIconInfo->SetIcon(icon);

    EXPECT_EQ(bundleIconInfo->GetBundleName(), "bundle.setter");
    EXPECT_EQ(bundleIconInfo->GetUid(), TEST_UID);
    EXPECT_EQ(bundleIconInfo->GetAppIndex(), TEST_APP_INDEX);
    EXPECT_EQ(bundleIconInfo->GetIcon(), icon);
}

/**
 * @tc.name: Marshalling_00001
 * @tc.desc: Test Marshalling and Unmarshalling round trip with icon.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationBundleIconInfoTest, Marshalling_00001, Function | SmallTest | Level1)
{
    auto icon = TestMakePixelMap(ICON_SIZE, ICON_SIZE);
    ASSERT_NE(icon, nullptr);
    NotificationBundleIconInfo bundleIconInfo("bundle.test", TEST_UID, TEST_APP_INDEX, icon);

    Parcel parcel;
    EXPECT_TRUE(bundleIconInfo.Marshalling(parcel));

    auto *result = NotificationBundleIconInfo::Unmarshalling(parcel);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->GetBundleName(), "bundle.test");
    EXPECT_EQ(result->GetUid(), TEST_UID);
    EXPECT_EQ(result->GetAppIndex(), TEST_APP_INDEX);
    ASSERT_NE(result->GetIcon(), nullptr);
    EXPECT_EQ(result->GetIcon()->GetWidth(), icon->GetWidth());
    EXPECT_EQ(result->GetIcon()->GetHeight(), icon->GetHeight());
    delete result;
}

/**
 * @tc.name: Marshalling_IconEmpty_00001
 * @tc.desc: Test Marshalling and Unmarshalling round trip with empty icon.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationBundleIconInfoTest, Marshalling_IconEmpty_00001, Function | SmallTest | Level1)
{
    std::shared_ptr<Media::PixelMap> emptyIcon = nullptr;
    NotificationBundleIconInfo bundleIconInfo("bundle.empty", TEST_UID, TEST_APP_INDEX, emptyIcon);

    Parcel parcel;
    EXPECT_TRUE(bundleIconInfo.Marshalling(parcel));

    auto *result = NotificationBundleIconInfo::Unmarshalling(parcel);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->GetBundleName(), "bundle.empty");
    EXPECT_EQ(result->GetUid(), TEST_UID);
    EXPECT_EQ(result->GetAppIndex(), TEST_APP_INDEX);
    EXPECT_EQ(result->GetIcon(), nullptr);
    delete result;
}

/**
 * @tc.name: Dump_00001
 * @tc.desc: Test Dump does not crash with and without icon.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationBundleIconInfoTest, Dump_00001, Function | SmallTest | Level1)
{
    auto icon = TestMakePixelMap(ICON_SIZE, ICON_SIZE);
    ASSERT_NE(icon, nullptr);
    NotificationBundleIconInfo bundleIconInfoWithIcon("bundle.dump", TEST_UID, TEST_APP_INDEX, icon);
    EXPECT_FALSE(bundleIconInfoWithIcon.Dump().empty());
    EXPECT_NE(bundleIconInfoWithIcon.Dump().find("bundle.dump"), std::string::npos);

    NotificationBundleIconInfo bundleIconInfoWithoutIcon;
    EXPECT_FALSE(bundleIconInfoWithoutIcon.Dump().empty());
}
}  // namespace Notification
}  // namespace OHOS
