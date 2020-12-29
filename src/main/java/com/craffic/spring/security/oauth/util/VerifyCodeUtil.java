package com.craffic.spring.security.oauth.util;

import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Random;

/**
 * 生成验证码的工具类
 */
public class VerifyCodeUtil {

    // 生成验证码图片的宽度
    private int width = 100;
    // 生成验证码图片的高度
    private int heigth = 50;
    // 字体风格集合
    private String[] fontNames = { "宋体", "楷体", "隶书", "微软雅黑" };
    // 定义验证码图片的背景颜色为白色
    private Color bgColor = new Color(255, 255, 255);
    private Random random = new Random();
    private String codes = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    // 记录随机字符串
    private String text;

    /**
     * 获取一个随意颜色
     */
    private Color getRandomColor(){
        int red = random.nextInt(150);
        int green = random.nextInt(150);
        int blue = random.nextInt(150);
        return new Color(red, green, blue);
    }

    /**
     * 获取一个随机字体
     */
    private Font getRandomFont(){
        String fontName = fontNames[random.nextInt(fontNames.length)];
        int style = random.nextInt(4);
        int size = random.nextInt(5) + 24;
        return new Font(fontName, style, size);
    }

    /**
     * 获取一个随机字符
     */
    private char getRandomChar(){
        return codes.charAt(random.nextInt(codes.length()));
    }

    /**
     * 创建一个空白的BufferedImage对象
     */
    private BufferedImage createImage(){
        BufferedImage image = new BufferedImage(width, heigth, BufferedImage.TYPE_INT_RGB);
        Graphics2D graphics = (Graphics2D)image.getGraphics();
        // 设置验证码图片的背景颜色
        graphics.setColor(bgColor);
        graphics.fillRect(0, 0, width, heigth);
        return image;
    }

    public BufferedImage getImage(){
        BufferedImage image = createImage();
        Graphics2D graphics = (Graphics2D) image.getGraphics();
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < 4; i++) {
            String tempStr = getRandomChar() + "";
            sb.append(tempStr);
            graphics.setColor(getRandomColor());
            graphics.setFont(getRandomFont());
            float x = i * width * 1.0f / 4;
            graphics.drawString(tempStr, x, heigth - 15);
        }
        this.text = sb.toString();
        drawLine(image);
        return image;
    }

    /**
     * 绘制干扰线
     *
     * @param image
     */
    private void drawLine(BufferedImage image) {
        Graphics2D g2 = (Graphics2D) image.getGraphics();
        int num = 5;
        for (int i = 0; i < num; i++) {
            int x1 = random.nextInt(width);
            int y1 = random.nextInt(heigth);
            int x2 = random.nextInt(width);
            int y2 = random.nextInt(heigth);
            g2.setColor(getRandomColor());
            g2.setStroke(new BasicStroke(1.5f));
            g2.drawLine(x1, y1, x2, y2);
        }
    }

    public String getText() {
        return text;
    }

    public static void output(BufferedImage image, OutputStream out) throws IOException {
        ImageIO.write(image, "JPEG", out);
    }


}
