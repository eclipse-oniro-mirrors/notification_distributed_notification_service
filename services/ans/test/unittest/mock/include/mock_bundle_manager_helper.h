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

#ifndef ANS_MOCK_BUNDLE_MANAGER_HELPER_H
#define ANS_MOCK_BUNDLE_MANAGER_HELPER_H

#include <cstdint>

#include "notification_bundle_option.h"

namespace OHOS::Notification {
class MockBundleManager {
public:
    static void MockBundleRseult(bool result);
    static void MockSystemBundle(bool systemBundle);
    static void MockClearInstalledBundle();
    static void MockBundleInterfaceResult(const int32_t result);
    static void MockInstallBundle(const NotificationBundleOption& bundleOption);
    static void MockUninstallBundle(const NotificationBundleOption& bundleOption);
};
}  // namespace OHOS::Notification

#endif  // ANS_MOCK_BUNDLE_MANAGER_HELPER_H
