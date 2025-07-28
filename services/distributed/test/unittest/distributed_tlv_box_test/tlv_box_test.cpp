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

#include <memory>

#include <securec.h>
#include "gtest/gtest.h"
#define private public
#include "remove_box.h"
#include "match_box.h"
#include "bundle_icon_box.h"
#include "batch_remove_box.h"
#include "notification_sync_box.h"
#include "request_box.h"
#include "response_box.h"
#include "state_box.h"
#include "ans_log_wrapper.h"

using namespace testing::ext;

namespace OHOS {
namespace Notification {
class TlvBoxTest : public testing::Test {
public:
    void SetUp() override {};
    void TearDown() override {};
};

/**
 * @tc.name   : Tlv box for bundle icon.
 * @tc.number : TlvBoxTest_0102
 * @tc.desc   : test tlv serialization and deserialization.
 */
HWTEST_F(TlvBoxTest, TlvBoxTest_BundleIcon_0100, Function | SmallTest | Level1)
{
    auto data = std::make_shared<BundleIconBox>();
    data->SetMessageType(BUNDLE_ICON_SYNC);
    data->SetIconSyncType(IconSyncType::REQUEST_BUNDLE_ICON);
    data->SetBundleList({"ohom.example.test"});
    data->SetLocalDeviceId("local_device");
    data->Serialize();
    int len = data->GetByteLength();
    unsigned char* cached = new unsigned char[len];
    errno_t err = memcpy_s(cached, len, data->GetByteBuffer(), len);
    if (err != EOK) {
        delete[] cached;
        EXPECT_EQ((int)err, (int)EOK);
    }
    bool result = TlvBox::CheckMessageCRC((const unsigned char*)cached, len);
    EXPECT_EQ(result, true);
    std::shared_ptr<TlvBox> box = std::make_shared<TlvBox>();
    result = box->Parse((const unsigned char*)cached, len - sizeof(uint32_t));
    EXPECT_EQ(result, true);
    delete[] cached;

    int32_t intData;
    BundleIconBox iconBox = BundleIconBox(box);
    EXPECT_EQ(iconBox.box_->GetMessageType(intData), true);
    EXPECT_EQ(intData, BUNDLE_ICON_SYNC);
    EXPECT_EQ(iconBox.GetIconSyncType(intData), true);
    EXPECT_EQ(intData, IconSyncType::REQUEST_BUNDLE_ICON);
    std::string stringData;
    EXPECT_EQ(iconBox.GetLocalDeviceId(stringData), true);
    EXPECT_EQ(stringData, "local_device");
    std::vector<std::string> bundleList;
    EXPECT_EQ(iconBox.GetBundleList(bundleList), true);
    EXPECT_EQ(bundleList.empty(), false);
    iconBox.box_ = nullptr;
    EXPECT_EQ(iconBox.SetMessageType(BUNDLE_ICON_SYNC), false);
    EXPECT_EQ(iconBox.SetIconSyncType(IconSyncType::REQUEST_BUNDLE_ICON), false);
    EXPECT_EQ(iconBox.SetBundleList({"ohom.example.test"}), false);
    EXPECT_EQ(iconBox.SetLocalDeviceId("local_device"), false);
    EXPECT_EQ(iconBox.SetDataLength(1), false);
    std::unordered_map<std::string, std::string> bundles;
    bundles.insert({"123", "abc"});
    EXPECT_EQ(iconBox.SetBundlesIcon(bundles), false);

    std::unordered_map<std::string, std::string> receiveBundles;
    EXPECT_EQ(iconBox.GetIconSyncType(intData), false);
    EXPECT_EQ(iconBox.GetLocalDeviceId(stringData), false);
    EXPECT_EQ(iconBox.GetBundleList(bundleList), false);
    EXPECT_EQ(iconBox.GetDataLength(intData), false);
    EXPECT_EQ(iconBox.GetBundlesIcon(receiveBundles), false);
}

/**
 * @tc.name   : Tlv box for bundle icon.
 * @tc.number : TlvBoxTest_0103
 * @tc.desc   : test tlv serialization and deserialization.
 */
HWTEST_F(TlvBoxTest, TlvBoxTest_BundleIcon_0101, Function | SmallTest | Level1)
{
    auto data = std::make_shared<BundleIconBox>();
    std::unordered_map<std::string, std::string> bundles;
    bundles.insert({"123", "abc"});
    data->SetBundlesIcon(bundles);
    data->Serialize();
    int len = data->GetByteLength();
    unsigned char* cached = new unsigned char[len];
    errno_t err = memcpy_s(cached, len, data->GetByteBuffer(), len);
    if (err != EOK) {
        delete[] cached;
        EXPECT_EQ((int)err, (int)EOK);
    }
    bool result = TlvBox::CheckMessageCRC((const unsigned char*)cached, len);
    EXPECT_EQ(result, true);
    std::shared_ptr<TlvBox> box = std::make_shared<TlvBox>();
    result = box->Parse((const unsigned char*)cached, len - sizeof(uint32_t));
    EXPECT_EQ(result, true);
    delete[] cached;

    bundles.clear();
    BundleIconBox iconBox = BundleIconBox(box);
    EXPECT_EQ(iconBox.GetBundlesIcon(bundles), true);
    EXPECT_EQ(bundles.empty(), false);
}

/**
 * @tc.name   : Tlv box for bundle icon.
 * @tc.number : TlvBoxTest_0103
 * @tc.desc   : test tlv serialization and deserialization.
 */
HWTEST_F(TlvBoxTest, TlvBoxTest_BundleIcon_0102, Function | SmallTest | Level1)
{
    auto data = std::make_shared<BundleIconBox>();
    std::vector<std::pair<std::string, std::string>> bundles;
    bundles.push_back(std::make_pair("com.oh.test", "test"));
    data->SetBundlesInfo(bundles);
    data->Serialize();
    int len = data->GetByteLength();
    unsigned char* cached = new unsigned char[len];
    errno_t err = memcpy_s(cached, len, data->GetByteBuffer(), len);
    if (err != EOK) {
        delete[] cached;
        EXPECT_EQ((int)err, (int)EOK);
    }
    bool result = TlvBox::CheckMessageCRC((const unsigned char*)cached, len);
    EXPECT_EQ(result, true);
    std::shared_ptr<TlvBox> box = std::make_shared<TlvBox>();
    result = box->Parse((const unsigned char*)cached, len - sizeof(uint32_t));
    EXPECT_EQ(result, true);
    delete[] cached;

    std::vector<std::string> bundle;
    std::vector<std::string> labels;
    BundleIconBox iconBox = BundleIconBox(box);
    EXPECT_EQ(iconBox.GetBundlesInfo(bundle, labels), true);
    EXPECT_EQ(bundles.empty(), false);
}
}  // namespace Notification
}  // namespace OHOS
