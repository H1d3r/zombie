//go:build go1.18
// +build go1.18

package pkg

import (
	"fmt"
	"github.com/chainreactors/logs"
	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
	"os"
	"time"
)

var Progress *mpb.Progress

func InitBar() {
	Progress = mpb.New(
		mpb.WithRefreshRate(200*time.Millisecond),
		mpb.WithOutput(os.Stdout),
	)
	logs.Log.SetOutput(Progress)
}

func NewBar(u string, total int, stat *Statistor) *Bar {
	if Progress == nil {
		return &Bar{
			url: u,
		}
	}
	bar := Progress.AddBar(int64(total),
		mpb.BarRemoveOnComplete(),
		mpb.PrependDecorators(
			decor.Name(u, decor.WC{W: len(u) + 1, C: decor.DindentRight}), // 这里调整了装饰器的参数
			decor.NewAverageSpeed(0, "% .0f/s ", time.Now()),
			decor.Counters(0, "%d/%d"),
			decor.Any(func(s decor.Statistics) string {
				return fmt.Sprintf(" %s", stat.Cur)
			}),
		),
		mpb.AppendDecorators(
			decor.Any(func(s decor.Statistics) string {
				return fmt.Sprintf("tasks: %d ", stat.Total)
			}),
			decor.Percentage(),
			decor.Elapsed(decor.ET_STYLE_GO, decor.WC{W: 4}),
		),
	)

	return &Bar{
		url: u,
		bar: bar,
		//m:   m,
	}
}

type Bar struct {
	url string
	bar *mpb.Bar
	//m   metrics.Meter
}

func (bar *Bar) Done() {
	//bar.m.Mark(1)
	if bar.bar == nil {
		return
	}
	bar.bar.Increment()
}

func (bar *Bar) Close() {
	//metrics.Unregister(bar.url)
	// 标记进度条为完成状态
	if bar.bar == nil {
		return
	}
	bar.bar.Abort(false)
}
