package com.coara.unpack;

import android.content.Context;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.ViewConfiguration;
import android.view.ViewParent;
import android.widget.ScrollView;

public final class EdgeAwareScrollView extends ScrollView {
    private final int touchSlop;
    private float downY;

    public EdgeAwareScrollView(Context context, AttributeSet attrs) {
        super(context, attrs);
        touchSlop = ViewConfiguration.get(context).getScaledTouchSlop();
    }

    private void disallowParent(boolean disallow) {
        ViewParent parent = getParent();
        if (parent != null) parent.requestDisallowInterceptTouchEvent(disallow);
    }

    @Override
    public boolean onInterceptTouchEvent(MotionEvent event) {
        int action = event.getActionMasked();
        if (action == MotionEvent.ACTION_DOWN) {
            downY = event.getY();
            disallowParent(true);
        } else if (action == MotionEvent.ACTION_MOVE) {
            float distance = downY - event.getY();
            if (Math.abs(distance) > touchSlop) {
                int direction = distance > 0 ? 1 : -1;
                disallowParent(canScrollVertically(direction));
            }
        } else if (action == MotionEvent.ACTION_UP || action == MotionEvent.ACTION_CANCEL) {
            disallowParent(false);
        }
        return super.onInterceptTouchEvent(event);
    }

    @Override
    public boolean onTouchEvent(MotionEvent event) {
        int action = event.getActionMasked();
        if (action == MotionEvent.ACTION_UP || action == MotionEvent.ACTION_CANCEL) disallowParent(false);
        return super.onTouchEvent(event);
    }
}
