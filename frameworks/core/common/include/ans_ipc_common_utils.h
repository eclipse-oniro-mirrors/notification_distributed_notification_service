/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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
#ifndef BASE_NOTIFICATION_ANS_STANDARD_CORE_IPC_COMMON_UTILS_H
#define BASE_NOTIFICATION_ANS_STANDARD_CORE_IPC_COMMON_UTILS_H

#include <securec.h>

#include "ans_log_wrapper.h"
#include "ans_const_define.h"
#include "ipc_skeleton.h"
#include "iremote_broker.h"
#include "notification_constant.h"

namespace OHOS {
namespace Notification {
class AnsIpcCommonUtils {
public:
    template<typename T>
    static bool WriteParcelableVector(const std::vector<std::shared_ptr<T>> &parcelableVector, Parcel &data)
    {
        if (!data.WriteInt32(parcelableVector.size())) {
            ANS_LOGE("Failed to write ParcelableVector size.");
            return false;
        }

        for (auto &parcelable : parcelableVector) {
            if (!data.WriteParcelable(parcelable.get())) {
                ANS_LOGE("Failed to write ParcelableVector");
                return false;
            }
        }
        return true;
    }

    template<typename T>
    static bool ReadParcelableVector(std::vector<std::shared_ptr<T>> &parcelableInfos, Parcel &data)
    {
        int32_t infoSize = 0;
        if (!data.ReadInt32(infoSize)) {
            ANS_LOGE("Failed to read Parcelable size.");
            return false;
        }
        infoSize = (infoSize < MAX_PARCELABLE_VECTOR_NUM) ? infoSize : MAX_PARCELABLE_VECTOR_NUM;
        parcelableInfos.clear();
        for (int32_t index = 0; index < infoSize; index++) {
            std::shared_ptr<T> info = std::shared_ptr<T>(data.ReadParcelable<T>());
            if (info == nullptr) {
                ANS_LOGE("Failed to read Parcelable infos.");
                return false;
            }
            parcelableInfos.emplace_back(info);
        }

        return true;
    }
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_ANS_STANDARD_CORE_IPC_COMMON_UTILS_H