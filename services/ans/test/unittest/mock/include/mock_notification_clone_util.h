/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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
#ifndef BASE_NOTIFICATION_MOCK_NOTIFICATION_CLONE_UTIL_H
#define BASE_NOTIFICATION_MOCK_NOTIFICATION_CLONE_UTIL_H

#include <gtest/gtest.h>
#include <gmock/gmock.h>

namespace OHOS {
namespace Notification {
void MockSetActiveUserIdForClone(int32_t userId);
void MockSetBundleUidForClone(int32_t uid);
void SetFuncGetActiveUserIdIsCalled(bool funcGetActiveUserIdIsCalled);
bool GetFuncGetActiveUserIdIsCalled();
void SetFuncGetBundleUidIsCalled(bool funcGetBundleUidIsCalled);
bool GetFuncGetBundleUidIsCalled();
}
}
#endif