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

#include "ffrt_queue_impl.h"

#include <vector>
#include "errors.h"
#include "ans_log_wrapper.h"
#include "ans_inner_errors.h"

namespace OHOS {
namespace Notification {
namespace Infra {

FfrtQueueImpl::FfrtQueueImpl(const std::string queueName) : name_(queueName)
{
    queue_ = std::make_shared<ffrt::queue>(name_.c_str());
    if (queue_ == nullptr) {
        ANS_LOGE("ffrt create failed %{public}s", name_.c_str());
    }
}

FfrtQueueImpl::~FfrtQueueImpl()
{
    ANS_LOGE("ffrt destory %{public}s", name_.c_str());
    if (queue_ == nullptr) {
        return;
    }
    queue_.reset();
}

void FfrtQueueImpl::PostTask(const std::function<void()>& func)
{
    ffrt::submit(func);
}

void FfrtQueueImpl::PostTask(const std::function<void()>& func, const int64_t delayTime, const std::string taskName)
{
    ffrt::submit(func, ffrt::task_attr().name(taskName.c_str()).delay(delayTime));
}

void FfrtQueueImpl::PostTask(const std::function<void()>&& func)
{
    ffrt::submit(std::move(func));
}

void FfrtQueueImpl::PostTask(const std::function<void()>&& func, const int64_t delayTime, const std::string taskName)
{
    ffrt::submit(std::move(func), ffrt::task_attr().name(taskName.c_str()).delay(delayTime));
}

int32_t FfrtQueueImpl::Submit(const std::function<void()>& func)
{
    if (queue_ == nullptr) {
        ANS_LOGE("Invalid queue %{public}s", name_.c_str());
        return ERR_ANS_INVALID_PARAM;
    }

    queue_->submit(func);
    return ERR_OK;
}

int32_t FfrtQueueImpl::Submit(const std::function<void()>&& func)
{
    if (queue_ == nullptr) {
        ANS_LOGE("Invalid queue %{public}s", name_.c_str());
        return ERR_ANS_INVALID_PARAM;
    }

    queue_->submit(std::move(func));
    return ERR_OK;
}


int32_t FfrtQueueImpl::Submit(const std::function<void()>& func, const int64_t delayTime, const std::string taskName)
{
    if (queue_ == nullptr) {
        ANS_LOGE("Invalid queue %{public}s", name_.c_str());
        return ERR_ANS_INVALID_PARAM;
    }

    queue_->submit(func, ffrt::task_attr().name(taskName.c_str()).delay(delayTime));
    return ERR_OK;
}

int32_t FfrtQueueImpl::Submit(const std::function<void()>&& func, const int64_t delayTime, const std::string taskName)
{
    if (queue_ == nullptr) {
        ANS_LOGE("Invalid queue %{public}s", name_.c_str());
        return ERR_ANS_INVALID_PARAM;
    }

    queue_->submit(std::move(func), ffrt::task_attr().name(taskName.c_str()).delay(delayTime));
    return ERR_OK;
}

int32_t FfrtQueueImpl::SyncSubmit(std::function<void()>& func)
{
    if (queue_ == nullptr) {
        ANS_LOGE("Invalid queue %{public}s", name_.c_str());
        return ERR_ANS_INVALID_PARAM;
    }

    ffrt::task_handle handler = queue_->submit_h(func);
    queue_->wait(handler);
    return ERR_OK;
}


int32_t FfrtQueueImpl::SyncSubmit(std::function<void()>&& func)
{
    if (queue_ == nullptr) {
        ANS_LOGE("Invalid queue %{public}s", name_.c_str());
        return ERR_ANS_INVALID_PARAM;
    }

    ffrt::task_handle handler = queue_->submit_h(std::move(func));
    queue_->wait(handler);
    return ERR_OK;
}

} // Infra
} // Notification
} // OHOS
