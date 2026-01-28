import React from "react";
import Svg, { G, Path, Rect } from "react-native-svg";

interface LogoIconProps {
  width?: number;
  height?: number;
  fill?: string;
}

const LogoIcon: React.FC<LogoIconProps> = ({
  width = 32,
  height = 33,
  fill = "#FFFFFF",
}) => {
  return (
    <Svg
      width="32px"
      height="32px"
      viewBox="0 0 3 3"
      fill="none"
    //   xmlns="http://www.w3.org/2000/svg"
    //   {...props}
    >
      <G id="SVGRepo_bgCarrier" strokeWidth={0} />
      <G
        id="SVGRepo_tracerCarrier"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <G id="SVGRepo_iconCarrier">
        <Path
          opacity={0.4}
          d="M0.35 1.935s0.018 0.217 0.022 0.286c0.005 0.092 0.041 0.195 0.1 0.266 0.084 0.101 0.182 0.137 0.314 0.137 0.154 0 1.279 0 1.433 0 0.132 0 0.23 -0.036 0.314 -0.137 0.059 -0.071 0.095 -0.174 0.1 -0.266 0.004 -0.069 0.022 -0.286 0.022 -0.286"
          stroke="#ffffff"
          strokeWidth={0.1875}
          strokeLinecap="round"
          strokeLinejoin="round"
        />
        <Path
          d="M1.062 0.666v-0.046c0 -0.152 0.123 -0.276 0.276 -0.276h0.323c0.152 0 0.276 0.123 0.276 0.276l0 0.046"
          stroke="#ffffff"
          strokeWidth={0.1875}
          strokeLinecap="round"
          strokeLinejoin="round"
        />
        <Path
          d="M1.499 2.085v-0.162"
          stroke="#ffffff"
          strokeWidth={0.1875}
          strokeLinecap="round"
          strokeLinejoin="round"
        />
        <Path
          fillRule="evenodd"
          clipRule="evenodd"
          d="M0.344 1.049v0.433c0.24 0.158 0.527 0.269 0.842 0.313a0.323 0.323 0 0 1 0.313 -0.238c0.148 0 0.275 0.101 0.31 0.24 0.317 -0.044 0.605 -0.155 0.846 -0.314V1.049a0.381 0.381 0 0 0 -0.382 -0.382H0.727A0.383 0.383 0 0 0 0.344 1.049"
          stroke="#ffffff"
          strokeWidth={0.1875}
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </G>
    </Svg>
    // <Svg
    // //   viewBox="0 0 24 24"
    // //   fill="none"
    // //   xmlns="http://www.w3.org/2000/svg"
    // //   width={width}
    // //   height={height}
    // //   viewBox="0 0 32 33"
    // //   fill="none"
    // // >
    //   width="256px"
    //   height="256px"
    //   viewBox="0 0 24 24"
    //   fill="none"
    // //   xmlns="http://www.w3.org/2000/svg"
    // //   {...props}
    // >
    //   <G id="SVGRepo_bgCarrier" strokeWidth={0} />
    //   <G
    //     id="SVGRepo_tracerCarrier"
    //     strokeLinecap="round"
    //     strokeLinejoin="round"
    //   />
    //   <G id="SVGRepo_iconCarrier">
    //     <Path
    //       opacity={0.4}
    //       d="M2.80408 15.4771C2.80408 15.4771 2.94608 17.2151 2.97908 17.7631C3.02308 18.4981 3.30708 19.3191 3.78108 19.8891C4.45008 20.6971 5.23808 20.9821 6.29008 20.9841C7.52708 20.9861 16.5221 20.9861 17.7591 20.9841C18.8111 20.9821 19.5991 20.6971 20.2681 19.8891C20.7421 19.3191 21.0261 18.4981 21.0711 17.7631C21.1031 17.2151 21.2451 15.4771 21.2451 15.4771"
    //       stroke="#ffffff"
    //       strokeWidth={1.5}
    //       strokeLinecap="round"
    //       strokeLinejoin="round"
    //     />
    //     <Path
    //       d="M8.49597 5.32949V4.95849C8.49597 3.73849 9.48397 2.75049 10.704 2.75049H13.286C14.505 2.75049 15.494 3.73849 15.494 4.95849L15.495 5.32949"
    //       stroke="#ffffff"
    //       strokeWidth={1.5}
    //       strokeLinecap="round"
    //       strokeLinejoin="round"
    //     />
    //     <Path
    //       d="M11.995 16.6783V15.3843"
    //       stroke="#ffffff"
    //       strokeWidth={1.5}
    //       strokeLinecap="round"
    //       strokeLinejoin="round"
    //     />
    //     <Path
    //       fillRule="evenodd"
    //       clipRule="evenodd"
    //       d="M2.74988 8.38905V11.8561C4.66788 13.1211 6.96588 14.0071 9.48788 14.3581C9.78988 13.2571 10.7829 12.4501 11.9899 12.4501C13.1779 12.4501 14.1909 13.2571 14.4729 14.3681C17.0049 14.0171 19.3119 13.1311 21.2399 11.8561V8.38905C21.2399 6.69505 19.8769 5.33105 18.1829 5.33105H5.81688C4.12288 5.33105 2.74988 6.69505 2.74988 8.38905Z"
    //       stroke="#ffffff"
    //       strokeWidth={1.5}
    //       strokeLinecap="round"
    //       strokeLinejoin="round"
    //     />
    //   </G>
    // </Svg>
    // <Svg width={width} height={height} viewBox="0 0 32 33" fill="none">
    //   <Path
    //     d="M4.32251 2.25C4.32251 1.00736 5.32987 0 6.57251 0H10.3225C11.5652 0 12.5725 1.00736 12.5725 2.25V8.56695C12.5725 9.3145 12.2012 10.0132 11.5817 10.4316L7.83172 12.964C6.3374 13.9731 4.32251 12.9025 4.32251 11.0994V2.25Z"
    //     fill={fill}
    //   />
    //   <Path
    //     d="M4.32251 22.325C4.32251 21.0824 5.32987 20.075 6.57251 20.075H10.3225C11.5652 20.075 12.5725 21.0824 12.5725 22.325V30.75C12.5725 31.9927 11.5652 33 10.3225 33H6.57251C5.32987 33 4.32251 31.9927 4.32251 30.75V22.325Z"
    //     fill={fill}
    //   />
    //   <Path
    //     d="M23.5725 2.25C23.5725 1.00736 24.5799 0 25.8225 0H29.5725C30.8152 0 31.8225 1.00736 31.8225 2.25V18.3419C31.8225 20.2178 29.6618 21.27 28.185 20.1131L24.435 17.1756C23.8906 16.7491 23.5725 16.096 23.5725 15.4044V2.25Z"
    //     fill={fill}
    //   />
    //   <Path
    //     d="M17.3167 9.88049C18.8114 8.87557 20.8222 9.94685 20.822 11.748L20.8216 15.2945C20.8215 16.0466 20.4456 16.749 19.8199 17.1662L7.82076 25.1673C6.32552 26.1644 4.3225 25.0925 4.3225 23.2953L4.32251 19.8149C4.32251 19.0658 4.69542 18.3657 5.31717 17.9477L17.3167 9.88049Z"
    //     fill={fill}
    //   />
    //   <Rect
    //     x="18.0725"
    //     y="24.75"
    //     width="2.75"
    //     height="2.75"
    //     rx="1.375"
    //     fill={fill}
    //   />
    //   <Rect
    //     x="18.0725"
    //     y="30.25"
    //     width="2.75"
    //     height="2.75"
    //     rx="1.375"
    //     fill={fill}
    //   />
    //   <Rect
    //     x="23.5725"
    //     y="24.75"
    //     width="2.75"
    //     height="2.75"
    //     rx="1.375"
    //     fill={fill}
    //   />
    //   <Rect
    //     x="23.5725"
    //     y="30.25"
    //     width="2.75"
    //     height="2.75"
    //     rx="1.375"
    //     fill={fill}
    //   />
    // </Svg>
  );
};

export default LogoIcon;
