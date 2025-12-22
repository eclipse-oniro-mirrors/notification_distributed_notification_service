/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef ANS_FFRT_QUEUE_IMPL_H
#define ANS_FFRT_QUEUE_IMPL_H

#include "ffrt.h"

namespace OHOS {
namespace Notification {
namespace Infra {
class FfrtQueueImpl {

    explicit FfrtQueueImpl(const std::string queueName);

    ~FfrtQueueImpl();

    /**
     * @brief Submits a task to ffrt queue.
     */
    static void PostTask(const std::function<void()>& func);

    /**
     * @brief Submits a task with a specified attribute to ffrt queue.
     */
    static void PostTask(const std::function<void()>& func, const int64_t delayTime, const std::string taskName);

    /**
     * @brief Submits a task to ffrt queue.
     */
    static void PostTask(const std::function<void()>&& func);

    /**
     * @brief Submits a task with a specified attribute to ffrt queue.
     */
    static void PostTask(const std::function<void()>&& func, const int64_t delayTime, const std::string taskName);

    /**
     * @brief Submits a task to this queue.
     */
    int32_t Submit(const std::function<void()>& func);

    /**
     * @brief Submits a task to this queue.
     */
    int32_t Submit(const std::function<void()>&& func);

    /**
     * @brief Submits a task with a specified attribute to this queue.
     */
    int32_t Submit(const std::function<void()>& func, const int64_t delayTime, const std::string taskName);

    /**
     * @brief Submits a task with a specified attribute to this queue.
     */
    int32_t Submit(const std::function<void()>&& func, const int64_t delayTime, const std::string taskName);

    /**
     * @brief Submits a sync task to this queue.
     */
    int32_t SyncSubmit(std::function<void()>& func);

    /**
     * @brief Submits a sync task to this queue.
     */
    int32_t SyncSubmit(std::function<void()>&& func);

private:
    std::string name_;
    std::shared_ptr<ffrt::queue> queue_ = nullptr;
};
} // namespace Infra
} // namespace Notification
} // namespace OHOS
#endif  // ANS_FFRT_QUEUE_IMPL_H
