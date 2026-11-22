using System.Windows;
using System.Windows.Data;
using System.Windows.Markup;
using SteamSentinel.Core.Reporting;

namespace SteamSentinel.App.Localization;

/// <summary>将显示文案键绑定到本地化索引器以支持界面热切换；非依赖属性目标回退为当前语言文本。</summary>
[MarkupExtensionReturnType(typeof(object))]
public sealed class TextExtension(string key) : MarkupExtension
{
    public string Key { get; } = key;

    public override object ProvideValue(IServiceProvider serviceProvider)
    {
        if (serviceProvider?.GetService(typeof(IProvideValueTarget)) is IProvideValueTarget target)
        {
            bool canBind = (target.TargetObject is DependencyObject && target.TargetProperty is DependencyProperty)
                || string.Equals(target.TargetObject?.GetType().FullName, "System.Windows.SharedDp", StringComparison.Ordinal);
            if (canBind)
            {
                return new Binding($"[{Key}]")
                {
                    Source = Localizer.Instance,
                    Mode = BindingMode.OneWay
                }.ProvideValue(serviceProvider);
            }
        }
        return DisplayText.Get(Key);
    }
}
