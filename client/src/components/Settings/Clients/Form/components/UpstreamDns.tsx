import React from 'react';
import { Trans, useTranslation } from 'react-i18next';

import { Controller, useFormContext } from 'react-hook-form';
import Examples from '../../../Dns/Upstream/Examples';
import { UINT32_RANGE } from '../../../../../helpers/constants';
import { Textarea } from '../../../../ui/Controls/Textarea';
import { ClientForm } from '../types';
import { Checkbox } from '../../../../ui/Controls/Checkbox';
import { Input } from '../../../../ui/Controls/Input';
import { trimLinesAndRemoveEmpty } from '../../../../../helpers/helpers';

export const UpstreamDns = () => {
    const { t } = useTranslation();

    const { control } = useFormContext<ClientForm>();

    return (
        <div title={t('upstream_dns')}>
            <div className="form__desc mb-3">
                <Trans
                    components={[
                        <a href="#dns" key="0">
                            link
                        </a>,
                    ]}>
                    upstream_dns_client_desc
                </Trans>
            </div>

            <Controller
                name="upstreams"
                control={control}
                render={({ field }) => (
                    <Textarea
                        {...field}
                        className="form-control form-control--textarea mb-5"
                        placeholder={t('upstream_dns')}
                        onBlur={(event) => {
                            const normalizedValue = trimLinesAndRemoveEmpty(event.target.value);
                            field.onBlur();
                            field.onChange(normalizedValue);
                        }}
                    />
                )}
            />

            <Examples />

            <div className="form__label--bold mt-5 mb-3">{t('upstream_dns_cache_configuration')}</div>

            <div className="form__group mb-2">
                <Controller
                    name="upstreams_cache_enabled"
                    control={control}
                    render={({ field }) => <Checkbox {...field} title={t('enable_upstream_dns_cache')} />}
                />
            </div>

            <div className="form__group form__group--settings">
                <label htmlFor="upstreams_cache_size" className="form__label">
                    {t('dns_cache_size')}
                </label>

                <Controller
                    name="upstreams_cache_size"
                    control={control}
                    render={({ field, fieldState }) => (
                        <Input
                            {...field}
                            type="number"
                            placeholder={t('enter_cache_size')}
                            error={fieldState.error?.message}
                            min={0}
                            max={UINT32_RANGE.MAX}
                        />
                    )}
                />
            </div>
        </div>
    );
};
